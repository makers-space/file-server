/**
 * Integration Controller
 *
 * Manages verified external API endpoints and safe delivery of file content
 * and metadata to them.
 *
 * Access model:
 *  - global integrations: registered/managed by admins (MANAGE_ALL_CONTENT),
 *    usable by every authenticated user once verified
 *  - user integrations: personal export destinations; registering requires
 *    CREATE_CONTENT (the premium hook), usable only by their owner
 *  - deliveries require the sender to hold read access on the file
 */

import Integration, {INTEGRATION_SCOPES, INTEGRATION_STATUSES} from '../models/integration.model.js';
import File from '../models/file.model.js';
import User from '../models/user.model.js';
import {asyncHandler} from '../middleware/app.middleware.js';
import {AppError} from '../middleware/error.middleware.js';
import {hasRight, RIGHTS} from '../config/rights.js';
import logger from '../utils/app.logger.js';
import {
    validateExternalUrl,
    deliverPayload,
    sendVerificationChallenge,
    contentChecksum,
    signPayload
} from '../utils/external.delivery.js';
import {getYjsService} from '../middleware/file.middleware.js';
import mongoose from 'mongoose';

const yjsService = getYjsService();

const DEFAULT_MAX_CONTENT_BYTES = 10 * 1024 * 1024; // 10MB
const maxContentBytes = () => parseInt(process.env.EXTERNAL_SHARE_MAX_CONTENT_BYTES);

const getUserId = (req) => {
    const userId = req.user?.id || req.user?._id;
    if (!userId) {
        throw new AppError('User ID not found in request', 401);
    }
    return userId.toString();
};

const isAdmin = (req) => hasRight(req.user?.roles || [], RIGHTS.MANAGE_ALL_CONTENT);

const loadIntegration = async (id, {withSecrets = false} = {}) => {
    if (!mongoose.Types.ObjectId.isValid(id)) {
        throw new AppError('Invalid integration ID', 400);
    }
    const query = Integration.findById(id);
    if (withSecrets) {
        query.select('+signingSecret +apiKey');
    }
    const integration = await query;
    if (!integration) {
        throw new AppError('Integration not found', 404);
    }
    return integration;
};

const assertCanManage = (req, integration) => {
    if (isAdmin(req)) return;
    if (!integration.isOwnedBy(getUserId(req))) {
        throw new AppError('Only the integration owner or an admin can manage this integration', 403);
    }
};

const integrationController = {

    /**
     * @desc    Register a new external integration
     * @route   POST /api/v1/integrations
     * @access  Private (global scope: MANAGE_ALL_CONTENT; user scope: CREATE_CONTENT)
     */
    createIntegration: asyncHandler(async (req, res) => {
        const userId = getUserId(req);
        const {name, description, baseUrl, apiKey, apiKeyHeader, scope = INTEGRATION_SCOPES.USER} = req.body;

        if (scope === INTEGRATION_SCOPES.GLOBAL && !isAdmin(req)) {
            return res.status(403).json({
                success: false,
                message: 'Only admins can register global integrations'
            });
        }

        if (scope === INTEGRATION_SCOPES.USER && !hasRight(req.user.roles, RIGHTS.CREATE_CONTENT)) {
            return res.status(403).json({
                success: false,
                message: 'Personal integrations require an upgraded account'
            });
        }

        // SSRF / safety validation happens before anything is persisted
        await validateExternalUrl(baseUrl);

        const signingSecret = Integration.generateSigningSecret();

        const integration = await Integration.create({
            name,
            description,
            baseUrl,
            apiKey: apiKey || null,
            apiKeyHeader: apiKeyHeader || 'X-Api-Key',
            scope,
            owner: userId,
            signingSecret,
            status: INTEGRATION_STATUSES.PENDING
        });

        logger.info('External integration registered', {
            integrationId: integration._id.toString(),
            scope,
            owner: userId
        });

        res.status(201).json({
            success: true,
            message: 'Integration registered. Verify the endpoint before sending files.',
            integration: integration.toJSON(),
            // Shown exactly once so the receiver can be configured to verify signatures
            signingSecret
        });
    }),

    /**
     * @desc    List integrations visible to the requester
     * @route   GET /api/v1/integrations
     * @access  Private (admins see all; users see global + their own)
     */
    listIntegrations: asyncHandler(async (req, res) => {
        const userId = getUserId(req);

        const query = isAdmin(req)
            ? {}
            : {$or: [{scope: INTEGRATION_SCOPES.GLOBAL}, {owner: userId}]};

        const integrations = await Integration.find(query)
            .sort({createdAt: -1})
            .limit(200);

        res.status(200).json({
            success: true,
            count: integrations.length,
            integrations: integrations.map(i => i.toJSON())
        });
    }),

    /**
     * @desc    Get a single integration
     * @route   GET /api/v1/integrations/:integrationId
     * @access  Private (admin, owner, or any user for global integrations)
     */
    getIntegration: asyncHandler(async (req, res) => {
        const userId = getUserId(req);
        const integration = await loadIntegration(req.params.integrationId);

        const visible = isAdmin(req)
            || integration.scope === INTEGRATION_SCOPES.GLOBAL
            || integration.isOwnedBy(userId);

        if (!visible) {
            throw new AppError('Integration not found', 404);
        }

        res.status(200).json({success: true, integration: integration.toJSON()});
    }),

    /**
     * @desc    Update integration details. Changing the URL resets verification.
     * @route   PATCH /api/v1/integrations/:integrationId
     * @access  Private (owner or admin)
     */
    updateIntegration: asyncHandler(async (req, res) => {
        const integration = await loadIntegration(req.params.integrationId);
        assertCanManage(req, integration);

        const {name, description, baseUrl, apiKey, apiKeyHeader, status} = req.body;

        if (name !== undefined) integration.name = name;
        if (description !== undefined) integration.description = description;
        if (apiKeyHeader !== undefined) integration.apiKeyHeader = apiKeyHeader;
        if (apiKey !== undefined) integration.apiKey = apiKey || null;

        if (baseUrl !== undefined && baseUrl !== integration.baseUrl) {
            await validateExternalUrl(baseUrl);
            integration.baseUrl = baseUrl;
            // A new destination must re-verify before receiving files
            integration.status = INTEGRATION_STATUSES.PENDING;
            integration.verifiedAt = null;
        }

        // Only explicit enable/disable transitions are allowed here;
        // "verified" can only be reached through the verification handshake
        if (status === INTEGRATION_STATUSES.DISABLED) {
            integration.status = INTEGRATION_STATUSES.DISABLED;
        }

        await integration.save();

        res.status(200).json({
            success: true,
            message: 'Integration updated',
            integration: integration.toJSON()
        });
    }),

    /**
     * @desc    Delete an integration
     * @route   DELETE /api/v1/integrations/:integrationId
     * @access  Private (owner or admin)
     */
    deleteIntegration: asyncHandler(async (req, res) => {
        const integration = await loadIntegration(req.params.integrationId);
        assertCanManage(req, integration);

        await integration.deleteOne();

        res.status(200).json({success: true, message: 'Integration deleted'});
    }),

    /**
     * @desc    Run the challenge/response verification handshake
     * @route   POST /api/v1/integrations/:integrationId/verify
     * @access  Private (owner or admin)
     */
    verifyIntegration: asyncHandler(async (req, res) => {
        const integration = await loadIntegration(req.params.integrationId, {withSecrets: true});
        assertCanManage(req, integration);

        if (integration.status === INTEGRATION_STATUSES.DISABLED) {
            return res.status(400).json({
                success: false,
                message: 'Integration is disabled. Re-enable it before verifying.'
            });
        }

        const {verified, error} = await sendVerificationChallenge(integration);

        if (verified) {
            integration.status = INTEGRATION_STATUSES.VERIFIED;
            integration.verifiedAt = new Date();
            integration.lastVerificationError = null;
        } else {
            integration.status = INTEGRATION_STATUSES.PENDING;
            integration.lastVerificationError = error;
        }
        await integration.save();

        if (!verified) {
            return res.status(422).json({
                success: false,
                message: `Verification failed: ${error}`,
                integration: integration.toJSON()
            });
        }

        res.status(200).json({
            success: true,
            message: 'Integration verified',
            integration: integration.toJSON()
        });
    }),

    /**
     * @desc    Rotate the signing secret (invalidates the old one immediately)
     * @route   POST /api/v1/integrations/:integrationId/rotate-secret
     * @access  Private (owner or admin)
     */
    rotateSecret: asyncHandler(async (req, res) => {
        const integration = await loadIntegration(req.params.integrationId, {withSecrets: true});
        assertCanManage(req, integration);

        const signingSecret = Integration.generateSigningSecret();
        integration.signingSecret = signingSecret;
        await integration.save();

        res.status(200).json({
            success: true,
            message: 'Signing secret rotated',
            signingSecret
        });
    }),

    /**
     * @desc    Send file content and/or metadata to a verified integration
     * @route   POST /api/v1/integrations/:integrationId/send
     * @access  Private (requires read access to the file; user-scope: owner only)
     */
    sendFile: asyncHandler(async (req, res) => {
        const userId = getUserId(req);
        const {filePath, includeContent = false, event = 'file.export'} = req.body;

        const integration = await loadIntegration(req.params.integrationId, {withSecrets: true});

        if (integration.status === INTEGRATION_STATUSES.DISABLED) {
            return res.status(403).json({success: false, message: 'Integration is disabled'});
        }

        if (integration.status !== INTEGRATION_STATUSES.VERIFIED) {
            return res.status(403).json({
                success: false,
                message: 'Integration endpoint has not been verified. Files can only be sent to verified endpoints.'
            });
        }

        if (!integration.canBeUsedBy(userId)) {
            return res.status(403).json({
                success: false,
                message: 'You do not have access to this integration'
            });
        }

        // Sender must hold read permission on the file
        const file = await File.findOneWithReadPermission(
            {filePath, type: {$ne: 'directory'}},
            userId,
            req.user.roles || []
        );

        if (!file) {
            return res.status(404).json({
                success: false,
                message: 'File not found or you do not have permission to access it'
            });
        }

        const payload = {
            type: 'file.export',
            event,
            sentAt: new Date().toISOString(),
            sender: {
                id: userId,
                username: req.user.username || null
            },
            file: {
                fileName: file.fileName,
                filePath: file.filePath,
                fileType: file.type,
                mimeType: file.mimeType,
                size: file.size,
                tags: file.tags || [],
                description: file.description || '',
                createdAt: file.createdAt,
                updatedAt: file.updatedAt
            }
        };

        if (includeContent) {
            if (file.size > maxContentBytes()) {
                return res.status(413).json({
                    success: false,
                    message: `File exceeds the maximum external transfer size of ${maxContentBytes()} bytes`
                });
            }

            let content;
            let encoding;
            if (file.type === 'text') {
                content = file.filePath ? await yjsService.getTextContent(file.filePath) : '';
                encoding = 'utf-8';
            } else {
                content = await file.getContent(); // base64
                encoding = 'base64';
            }

            const contentBytes = encoding === 'base64'
                ? Buffer.byteLength(content || '', 'base64')
                : Buffer.byteLength(content || '', 'utf-8');

            if (contentBytes > maxContentBytes()) {
                return res.status(413).json({
                    success: false,
                    message: `File exceeds the maximum external transfer size of ${maxContentBytes()} bytes`
                });
            }

            payload.file.content = content;
            payload.file.contentEncoding = encoding;
            payload.file.checksum = contentChecksum(content || '');
            payload.file.checksumAlgorithm = 'sha256';
        }

        const result = await deliverPayload(integration, payload, {event});

        integration.recordDelivery({
            filePath: file.filePath,
            event,
            success: result.success,
            httpStatus: result.httpStatus,
            error: result.error,
            includedContent: !!includeContent,
            sentBy: userId,
            durationMs: result.durationMs
        });
        await integration.save();

        if (!result.success) {
            return res.status(502).json({
                success: false,
                message: `Delivery failed: ${result.error}`,
                delivery: {
                    httpStatus: result.httpStatus,
                    durationMs: result.durationMs
                }
            });
        }

        res.status(200).json({
            success: true,
            message: 'File delivered to external endpoint',
            delivery: {
                httpStatus: result.httpStatus,
                durationMs: result.durationMs,
                includedContent: !!includeContent
            }
        });
    }),

    /**
     * @desc    Recent delivery log for an integration
     * @route   GET /api/v1/integrations/:integrationId/deliveries
     * @access  Private (owner or admin)
     */
    getDeliveries: asyncHandler(async (req, res) => {
        const integration = await loadIntegration(req.params.integrationId);
        assertCanManage(req, integration);

        res.status(200).json({
            success: true,
            stats: integration.stats,
            deliveries: integration.deliveryLog
        });
    }),

    /**
     * @desc    Issue (or rotate) the inbound API key the external app uses to
     *          pull granted files. Returned in plain form exactly once.
     * @route   POST /api/v1/integrations/:integrationId/inbound-key
     * @access  Private (owner or admin)
     */
    issueInboundKey: asyncHandler(async (req, res) => {
        const integration = await loadIntegration(req.params.integrationId);
        assertCanManage(req, integration);

        const inboundKey = Integration.generateInboundKey();
        integration.inboundKeyHash = Integration.hashInboundKey(inboundKey);
        integration.inboundKeyIssuedAt = new Date();
        await integration.save();

        logger.info(`🔑 Inbound key issued for integration ${integration.name} (${integration.id})`);
        res.status(200).json({
            success: true,
            message: 'Inbound API key issued — copy it now, it will not be shown again',
            inboundKey,
            integration
        });
    }),

    /**
     * @desc    Replace the read grants (path prefixes the external app may fetch)
     * @route   PUT /api/v1/integrations/:integrationId/grants
     * @access  Private (owner or admin)
     */
    setGrants: asyncHandler(async (req, res) => {
        const integration = await loadIntegration(req.params.integrationId);
        assertCanManage(req, integration);

        const grants = (req.body.grants || []).map(({path}) => {
            let normalized = String(path || '').trim();
            if (!normalized.startsWith('/')) {
                throw new AppError(`Grant paths must be absolute (got "${path}")`, 400);
            }
            if (normalized.length > 1 && normalized.endsWith('/')) {
                normalized = normalized.slice(0, -1);
            }
            return {path: normalized, access: 'read'};
        });

        integration.grants = grants;
        await integration.save();

        res.status(200).json({
            success: true,
            message: 'Grants updated',
            integration
        });
    }),

    /**
     * @desc    Authenticate an external app by inbound API key (X-FSOne-Key)
     * @route   middleware for /api/v1/integrations/external/*
     * @access  External (no session)
     */
    verifyIntegrationKey: asyncHandler(async (req, _res, next) => {
        const key = req.headers['x-fsone-key'];
        if (!key || typeof key !== 'string' || !key.startsWith('fso_')) {
            throw new AppError('Missing or malformed X-FSOne-Key header', 401);
        }

        const integration = await Integration
            .findOne({inboundKeyHash: Integration.hashInboundKey(key)})
            .select('+inboundKeyHash +signingSecret');

        if (!integration) {
            logger.warn('Inbound integration request with unknown key', {ip: req.ip});
            throw new AppError('Invalid inbound API key', 401);
        }
        if (integration.status !== INTEGRATION_STATUSES.VERIFIED) {
            throw new AppError('Integration is not verified or has been disabled', 403);
        }

        const owner = await User.findById(integration.owner);
        if (!owner || owner.active === false) {
            throw new AppError('Integration owner account is not active', 403);
        }

        req.integration = integration;
        req.integrationOwner = owner;
        next();
    }),

    /**
     * @desc    Fetch a granted file (metadata, optionally content) as an
     *          external app. Response is HMAC-signed with the integration's
     *          signing secret (X-FSOne-Signature over `${timestamp}.${body}`).
     * @route   GET /api/v1/integrations/external/files?path=/x/y.txt&content=true
     * @access  External (inbound API key)
     */
    externalGetFile: asyncHandler(async (req, res) => {
        const integration = req.integration;
        const owner = req.integrationOwner;
        const filePath = String(req.query.path || '');
        const wantContent = req.query.content === 'true';

        const recordInbound = async (denied) => {
            integration.inboundStats.totalRequests += 1;
            if (denied) integration.inboundStats.deniedRequests += 1;
            integration.inboundStats.lastRequestAt = new Date();
            try { await integration.save(); } catch { /* stats are best-effort */ }
        };

        if (!integration.grantsPath(filePath)) {
            await recordInbound(true);
            throw new AppError('Path is not covered by this integration\'s grants', 403);
        }

        // Access is the intersection of the grant and the owner's own rights
        const file = await File.findOneWithReadPermission(
            {filePath, type: {$ne: 'directory'}},
            owner._id.toString(),
            owner.roles || []
        );
        if (!file) {
            await recordInbound(true);
            throw new AppError('File not found or not accessible', 404);
        }

        const response = {
            success: true,
            integration: {id: integration.id, name: integration.name},
            file: {
                fileName: file.fileName,
                filePath: file.filePath,
                fileType: file.type,
                mimeType: file.mimeType,
                size: file.size,
                tags: file.tags || [],
                description: file.description || '',
                createdAt: file.createdAt,
                updatedAt: file.updatedAt
            }
        };

        if (wantContent) {
            if (file.size > maxContentBytes()) {
                await recordInbound(true);
                throw new AppError(`File exceeds the maximum external transfer size of ${maxContentBytes()} bytes`, 413);
            }
            let content;
            let encoding;
            if (file.type === 'text') {
                content = file.filePath ? await yjsService.getTextContent(file.filePath) : '';
                encoding = 'utf-8';
            } else {
                content = await file.getContent(); // base64
                encoding = 'base64';
            }
            response.file.content = content;
            response.file.contentEncoding = encoding;
            response.file.checksum = contentChecksum(content || '');
            response.file.checksumAlgorithm = 'sha256';
        }

        await recordInbound(false);

        const body = JSON.stringify(response);
        const timestamp = Date.now().toString();
        res.set('X-FSOne-Timestamp', timestamp);
        res.set('X-FSOne-Signature', signPayload(integration.signingSecret, timestamp, body));
        res.status(200).type('application/json').send(body);
    })
};

export default integrationController;
