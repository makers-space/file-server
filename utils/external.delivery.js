/**
 * External delivery utility
 *
 * Safely sends file content and metadata to verified external APIs.
 *
 * Safety measures:
 *  - HTTPS-only by default (EXTERNAL_SHARE_ALLOW_HTTP=true relaxes for dev/test)
 *  - DNS resolution + private/reserved IP blocking to prevent SSRF
 *    (EXTERNAL_SHARE_ALLOW_PRIVATE=true relaxes for dev/test)
 *  - No credentials permitted inside URLs
 *  - Redirects are never followed
 *  - Request timeout and response size caps
 *  - Every payload is HMAC-SHA256 signed (X-FSOne-Signature) with a
 *    per-integration secret plus timestamp to prevent tampering/replay
 */

import axios from 'axios';
import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import net from 'node:net';
import logger from './app.logger.js';
import {AppError} from '../middleware/error.middleware.js';

const DEFAULT_TIMEOUT_MS = 10000;
const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024; // 1MB response cap

// ---------------------------------------------------------------------------
// Config helpers (read at call time so tests can toggle via process.env)
// ---------------------------------------------------------------------------

const allowHttp = () => process.env.EXTERNAL_SHARE_ALLOW_HTTP === 'true';
const allowPrivate = () => process.env.EXTERNAL_SHARE_ALLOW_PRIVATE === 'true';
const requestTimeoutMs = () => parseInt(process.env.EXTERNAL_SHARE_TIMEOUT_MS);

// ---------------------------------------------------------------------------
// SSRF protection
// ---------------------------------------------------------------------------

/**
 * Determine whether an IP address is private, loopback, link-local or
 * otherwise reserved — destinations we must never send user data to.
 */
export const isPrivateAddress = (ip) => {
    if (!ip) return true;

    // Normalize IPv4-mapped IPv6 (::ffff:10.0.0.1)
    const mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
    if (mapped) ip = mapped[1];

    if (net.isIPv4(ip)) {
        const octets = ip.split('.').map(Number);
        const [a, b] = octets;
        if (a === 0) return true;                       // 0.0.0.0/8
        if (a === 10) return true;                      // 10.0.0.0/8
        if (a === 127) return true;                     // 127.0.0.0/8 loopback
        if (a === 169 && b === 254) return true;        // 169.254.0.0/16 link-local (cloud metadata!)
        if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
        if (a === 192 && b === 168) return true;        // 192.168.0.0/16
        if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
        if (a >= 224) return true;                      // multicast + reserved
        return false;
    }

    if (net.isIPv6(ip)) {
        const lower = ip.toLowerCase();
        if (lower === '::' || lower === '::1') return true;   // unspecified / loopback
        if (lower.startsWith('fe8') || lower.startsWith('fe9') ||
            lower.startsWith('fea') || lower.startsWith('feb')) return true; // fe80::/10 link-local
        if (lower.startsWith('fc') || lower.startsWith('fd')) return true;   // fc00::/7 unique local
        return false;
    }

    // Not a recognizable IP — treat as unsafe
    return true;
};

/**
 * Validate an external URL for safe delivery.
 * Throws AppError(400) when the URL must not be used.
 *
 * @param {string} rawUrl - URL to validate
 * @returns {Promise<URL>} - Parsed URL when valid
 */
export const validateExternalUrl = async (rawUrl) => {
    let url;
    try {
        url = new URL(rawUrl);
    } catch {
        throw new AppError('Integration URL is not a valid URL', 400);
    }

    if (url.username || url.password) {
        throw new AppError('Integration URL must not contain credentials', 400);
    }

    if (url.protocol !== 'https:') {
        if (!(url.protocol === 'http:' && allowHttp())) {
            throw new AppError('Integration URL must use HTTPS', 400);
        }
    }

    const hostname = url.hostname.replace(/^\[|\]$/g, ''); // strip IPv6 brackets

    // Literal IP hostnames are validated directly
    if (net.isIP(hostname)) {
        if (isPrivateAddress(hostname) && !allowPrivate()) {
            throw new AppError('Integration URL resolves to a private or reserved address', 400);
        }
        return url;
    }

    if (hostname === 'localhost' && !allowPrivate()) {
        throw new AppError('Integration URL resolves to a private or reserved address', 400);
    }

    // Resolve DNS and block private targets (basic SSRF guard)
    if (!allowPrivate()) {
        let addresses;
        try {
            addresses = await dns.lookup(hostname, {all: true, verbatim: true});
        } catch {
            throw new AppError('Integration URL hostname could not be resolved', 400);
        }
        for (const {address} of addresses) {
            if (isPrivateAddress(address)) {
                throw new AppError('Integration URL resolves to a private or reserved address', 400);
            }
        }
    }

    return url;
};

// ---------------------------------------------------------------------------
// Payload signing
// ---------------------------------------------------------------------------

/**
 * Compute the HMAC-SHA256 signature for an outgoing payload.
 * Signature base string: `${timestamp}.${rawBody}`
 *
 * @param {string} secret - Integration signing secret
 * @param {string|number} timestamp - Unix epoch (ms)
 * @param {string} rawBody - Serialized JSON body
 * @returns {string} - hex signature, prefixed with sha256=
 */
export const signPayload = (secret, timestamp, rawBody) => {
    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(`${timestamp}.${rawBody}`);
    return `sha256=${hmac.digest('hex')}`;
};

/**
 * Compute a SHA-256 checksum for delivered file content so receivers can
 * verify integrity independent of transport.
 */
export const contentChecksum = (content) => {
    return crypto.createHash('sha256').update(content).digest('hex');
};

// ---------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------

const buildHeaders = (integration, rawBody, event) => {
    const timestamp = Date.now();
    const headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'FilesystemOne-Integration/1.0',
        'X-FSOne-Event': event,
        'X-FSOne-Timestamp': String(timestamp),
        'X-FSOne-Integration-Id': integration._id.toString(),
        'X-FSOne-Signature': signPayload(integration.signingSecret, timestamp, rawBody)
    };
    if (integration.apiKey) {
        headers[integration.apiKeyHeader || 'X-Api-Key'] = integration.apiKey;
    }
    return headers;
};

/**
 * POST a signed JSON payload to the integration endpoint.
 * The integration document MUST have been loaded with +signingSecret +apiKey.
 *
 * @returns {Promise<{success: boolean, httpStatus: number|null, error: string|null, durationMs: number, data: any}>}
 */
export const deliverPayload = async (integration, payload, {event = 'file.export'} = {}) => {
    // Re-validate the URL at send time — DNS may have changed since registration
    await validateExternalUrl(integration.baseUrl);

    const rawBody = JSON.stringify(payload);
    const headers = buildHeaders(integration, rawBody, event);
    const started = Date.now();

    try {
        const response = await axios.post(integration.baseUrl, rawBody, {
            headers,
            timeout: requestTimeoutMs(),
            maxRedirects: 0,                       // never follow redirects
            maxContentLength: DEFAULT_MAX_RESPONSE_BYTES,
            maxBodyLength: Infinity,
            validateStatus: () => true             // classify manually below
        });

        const durationMs = Date.now() - started;
        const success = response.status >= 200 && response.status < 300;

        if (!success) {
            logger.warn('External delivery rejected by receiver', {
                integrationId: integration._id.toString(),
                httpStatus: response.status,
                durationMs
            });
        }

        return {
            success,
            httpStatus: response.status,
            error: success ? null : `Receiver responded with status ${response.status}`,
            durationMs,
            data: response.data
        };
    } catch (error) {
        const durationMs = Date.now() - started;
        logger.warn('External delivery failed', {
            integrationId: integration._id.toString(),
            error: error.message,
            durationMs
        });
        return {
            success: false,
            httpStatus: error.response?.status ?? null,
            error: error.code === 'ECONNABORTED' ? 'Delivery timed out' : error.message,
            durationMs,
            data: null
        };
    }
};

/**
 * Challenge/response verification handshake.
 *
 * Sends a signed one-time challenge to the endpoint. The endpoint proves it
 * is a cooperating, correctly-configured receiver by echoing the challenge
 * back ({"challenge": "<value>"}) with a 2xx status.
 *
 * @returns {Promise<{verified: boolean, error: string|null}>}
 */
export const sendVerificationChallenge = async (integration) => {
    const challenge = crypto.randomBytes(24).toString('hex');
    const payload = {
        type: 'verification',
        integrationId: integration._id.toString(),
        challenge,
        issuedAt: new Date().toISOString()
    };

    const result = await deliverPayload(integration, payload, {event: 'integration.verify'});

    if (!result.success) {
        return {verified: false, error: result.error || 'Verification request failed'};
    }

    const echoed = result.data && typeof result.data === 'object'
        ? result.data.challenge
        : null;

    if (echoed !== challenge) {
        return {verified: false, error: 'Endpoint did not echo the verification challenge'};
    }

    return {verified: true, error: null};
};
