import multer from 'multer';
import path from 'node:path';
import zlib from 'node:zlib';
import {promisify} from 'node:util';
import File from '../models/file.model.js';
import logger from '../utils/app.logger.js';

// File Event Types for WebSocket Notifications
const FILE_EVENTS = {
    // File operations
    FILE_CREATED: 'file:created',
    FILE_DELETED: 'file:deleted',
    FILE_RENAMED: 'file:renamed',
    FILE_MOVED: 'file:moved',
    FILE_UPLOADED: 'file:uploaded',
    FILE_RESET: 'file:reset',       // Yjs document was atomically reset (delete/re-upload)
    
    // Directory operations
    DIRECTORY_CREATED: 'directory:created',
    DIRECTORY_DELETED: 'directory:deleted',
    DIRECTORY_RENAMED: 'directory:renamed',
    
    // Sharing operations
    FILE_SHARED: 'file:shared',
    FILE_UNSHARED: 'file:unshared',
    PERMISSIONS_CHANGED: 'permissions:changed',
    
    // Version operations
    VERSION_SAVED: 'version:saved',
    VERSION_DELETED: 'version:deleted',
    VERSION_LOADED: 'version:loaded',
    
    // Presence events
    USER_JOINED_FILE: 'user:joined:file',
    USER_LEFT_FILE: 'user:left:file',
    USER_ONLINE: 'user:online',
    USER_OFFLINE: 'user:offline',
    
    // System events
    CONNECTION_ESTABLISHED: 'connection:established',
    PING: 'ping',
    PONG: 'pong'
};

// Yjs imports for collaborative editing
import * as Y from 'yjs';
import { MongodbPersistence } from 'y-mongodb-provider';
import { RedisPersistence } from 'y-redis';
import mongoose from 'mongoose';
import jwt from 'jsonwebtoken';
import WebSocket from 'ws';
import {redisClient} from './app.middleware.js';

// Promisify zlib functions for async/await usage
const gzip = promisify(zlib.gzip);
const gunzip = promisify(zlib.gunzip);
const deflate = promisify(zlib.deflate);
const inflate = promisify(zlib.inflate);
const brotliCompress = promisify(zlib.brotliCompress);
const brotliDecompress = promisify(zlib.brotliDecompress);

// =============================================================================
// COMPRESSION CONFIGURATION
// =============================================================================

const COMPRESSION_CONFIG = {
    // Minimum file size to consider compression (1KB)
    minSizeForCompression: parseInt(process.env.COMPRESSION_MIN_SIZE) || 1024,
    minCompressionRatio: parseFloat(process.env.COMPRESSION_MIN_RATIO) || 0.05,

    // Compression algorithms and their priorities
    algorithms: {
        brotli: {priority: 1, extension: '.br', contentEncoding: 'br'},
        gzip: {priority: 2, extension: '.gz', contentEncoding: 'gzip'},
        deflate: {priority: 3, extension: '.deflate', contentEncoding: 'deflate'}
    },

    // Compression options
    options: {
        gzip: {level: 6, windowBits: 15, memLevel: 8},
        deflate: {level: 6, windowBits: 15, memLevel: 8},
        brotli: {
            params: {
                [zlib.constants.BROTLI_PARAM_QUALITY]: 6,
                [zlib.constants.BROTLI_PARAM_SIZE_HINT]: 0
            }
        }
    },

    // File types that benefit from compression
    compressibleTypes: [
        'text/',
        'application/json',
        'application/javascript',
        'application/xml',
        'application/x-javascript',
        'application/xhtml+xml',
        'application/rss+xml',
        'application/atom+xml',
        'image/svg+xml',
        'image/bmp',
        'image/tiff',
        'image/x-tiff',
        'image/tga',
        'image/x-tga',
        'image/ppm',
        'image/pgm',
        'image/pbm',
        'image/x-portable-anymap',
        'model/obj',
        'model/gltf+json',
        'model/vnd.collada+xml',
        'model/x3d+xml',
        'model/vrml'
    ],

    // File types that should not be compressed (already compressed)
    nonCompressibleTypes: [
        'image/jpeg',
        'image/jpg',
        'image/png',
        'image/gif',
        'image/webp',
        'image/avif',
        'image/heic',
        'image/heif',
        'image/jxl',
        'image/jp2',
        'image/jpx',
        'video/',
        'audio/',
        'application/zip',
        'application/rar',
        'application/7z',
        'application/gzip',
        'application/x-rar-compressed',
        'application/x-zip-compressed'
    ]
};

// =============================================================================
// COMPRESSION FUNCTIONS
// =============================================================================

/**
 * Determine if a file should be compressed based on type and size
 */
const shouldCompressFile = (mimeType, size) => {
    if (size < COMPRESSION_CONFIG.minSizeForCompression) return false;
    if (COMPRESSION_CONFIG.nonCompressibleTypes.some(type => mimeType.startsWith(type))) return false;
    return COMPRESSION_CONFIG.compressibleTypes.some(type => mimeType.startsWith(type));
};

/**
 * Compress file buffer using the best available algorithm
 */
const compressFileBuffer = async (buffer, mimeType, fileName) => {
    try {
        if (!shouldCompressFile(mimeType, buffer.length)) {
            return {
                compressed: false,
                buffer,
                originalSize: buffer.length,
                compressedSize: buffer.length,
                compressionRatio: 1,
                algorithm: 'none',
                contentEncoding: null
            };
        }

        const originalSize = buffer.length;
        let bestResult = null;
        let bestRatio = 1;

        for (const algorithm of ['brotli', 'gzip', 'deflate']) {
            try {
                const options = COMPRESSION_CONFIG.options[algorithm];
                let compressed;

                switch (algorithm) {
                    case 'brotli':  compressed = await brotliCompress(buffer, options); break;
                    case 'gzip':    compressed = await gzip(buffer, options); break;
                    case 'deflate': compressed = await deflate(buffer, options); break;
                }

                const ratio = compressed.length / originalSize;
                if (ratio < bestRatio) {
                    bestRatio = ratio;
                    bestResult = {
                        compressed: true,
                        buffer: compressed,
                        originalSize,
                        compressedSize: compressed.length,
                        compressionRatio: ratio,
                        algorithm,
                        contentEncoding: COMPRESSION_CONFIG.algorithms[algorithm].contentEncoding
                    };
                }
            } catch (err) {
                logger.warn(`Compression failed with ${algorithm}:`, { fileName, error: err.message });
            }
        }

        // Only compress if we save at least 5%
        if (bestRatio > 0.95) {
            return {
                compressed: false,
                buffer,
                originalSize,
                compressedSize: originalSize,
                compressionRatio: 1,
                algorithm: 'none',
                contentEncoding: null
            };
        }

        logger.info('File compressed successfully', {
            fileName,
            algorithm: bestResult.algorithm,
            originalSize,
            compressedSize: bestResult.compressedSize,
            spaceSaved: ((1 - bestRatio) * 100).toFixed(1) + '%'
        });

        return bestResult;
    } catch (error) {
        logger.error('Compression error:', { fileName, error: error.message });
        return {
            compressed: false,
            buffer,
            originalSize: buffer.length,
            compressedSize: buffer.length,
            compressionRatio: 1,
            algorithm: 'none',
            contentEncoding: null
        };
    }
};

/**
 * Decompress file buffer using the specified algorithm
 */
const decompressFileBuffer = async (buffer, algorithm, fileName) => {
    try {
        if (!algorithm || algorithm === 'none') return buffer;

        if (!Buffer.isBuffer(buffer)) {
            buffer = typeof buffer === 'string'
                ? Buffer.from(buffer, 'base64')
                : Buffer.from(String(buffer), 'base64');
        }

        switch (algorithm) {
            case 'brotli':  return await brotliDecompress(buffer);
            case 'gzip':    return await gunzip(buffer);
            case 'deflate': return await inflate(buffer);
            default: throw new Error(`Unsupported compression algorithm: ${algorithm}`);
        }
    } catch (error) {
        logger.error('Decompression error:', { fileName, algorithm, error: error.message });
        throw new Error(`Failed to decompress file: ${error.message}`);
    }
};

/**
 * Get compression statistics for monitoring
 */
const getCompressionStats = (originalSize, compressedSize, algorithm) => {
    if (typeof originalSize === 'number' && typeof compressedSize === 'number' && algorithm) {
        const spaceSaved = originalSize - compressedSize;
        return {
            originalSize,
            compressedSize,
            algorithm,
            compressionRatio: compressedSize / originalSize,
            spaceSaved,
            compressionPercentage: Math.round((spaceSaved / originalSize) * 100)
        };
    }

    return {
        config: {
            minSizeForCompression: COMPRESSION_CONFIG.minSizeForCompression,
            algorithms: Object.keys(COMPRESSION_CONFIG.algorithms),
            compressibleTypes: COMPRESSION_CONFIG.compressibleTypes.length,
            nonCompressibleTypes: COMPRESSION_CONFIG.nonCompressibleTypes.length
        },
        capabilities: {
            brotli: typeof zlib.brotliCompress === 'function',
            gzip: typeof zlib.gzip === 'function',
            deflate: typeof zlib.deflate === 'function'
        }
    };
};

// Configure multer for memory storage
const storage = multer.memoryStorage();

const fileFilter = (req, file, cb) => {
    try {
        // File type blocking can be configured via environment variable
        // BLOCKED_FILE_EXTENSIONS=".exe,.bat,.cmd,.scr,.vbs" (comma-separated)
        // Set to empty string to allow all file types
        const blockedExtensionsEnv = process.env.BLOCKED_FILE_EXTENSIONS;
        const blockedExtensions = blockedExtensionsEnv ?
            blockedExtensionsEnv.split(',').map(ext => ext.trim().toLowerCase()) :
            []; // Default: allow all file types

        const fileExt = path.extname(file.originalname).toLowerCase();

        if (blockedExtensions.length > 0 && blockedExtensions.includes(fileExt)) {
            logger.warn('Blocked file upload attempt', {
                originalname: file.originalname,
                mimetype: file.mimetype,
                extension: fileExt,
                blockedExtensions
            });
            return cb(new Error(`File type ${fileExt} is not allowed for security reasons`), false);
        }

        // Allow all other file types
        cb(null, true);
    } catch (error) {
        logger.error('File filter error:', error);
        cb(error, false);
    }
};

const upload = multer({
    storage,
    fileFilter,
    preservePath: true, // Keep directory paths in originalname for folder uploads
    limits: {
        fileSize: 500 * 1024 * 1024, // 500MB limit
        files: 20, // Max 20 files at once
        fieldNameSize: 200,
        fieldSize: 10 * 1024 * 1024, // 10MB for non-file fields
        fields: 50 // Max 50 non-file fields
    }
});

/**
 * Error handling middleware for file operations
 */
const handleFileErrors = (err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        let message = 'File upload error';
        let statusCode = 400;

        switch (err.code) {
            case 'LIMIT_FILE_SIZE':
                message = 'File too large. Maximum size is 500MB per file.';
                break;
            case 'LIMIT_FILE_COUNT':
                message = 'Too many files. Maximum 20 files allowed.';
                break;
            case 'LIMIT_UNEXPECTED_FILE':
                message = 'Unexpected file field.';
                break;
            case 'LIMIT_PART_COUNT':
                message = 'Too many parts in multipart form.';
                break;
            case 'LIMIT_FIELD_KEY':
                message = 'Field name too long.';
                break;
            case 'LIMIT_FIELD_VALUE':
                message = 'Field value too long.';
                break;
            case 'LIMIT_FIELD_COUNT':
                message = 'Too many fields.';
                break;
            default:
                message = `Upload error: ${err.message}`;
        }

        logger.warn('File upload error', {
            code: err.code,
            message: err.message,
            field: err.field
        });

        return res.status(statusCode).json({
            success: false,
            message: message,
            code: err.code
        });
    }

    // Handle compression/decompression errors
    if (err.message && err.message.includes('decompress')) {
        logger.error('File decompression error:', err);
        return res.status(500).json({
            success: false,
            message: 'Error processing compressed file',
            error: err.message
        });
    }

    // Pass other errors to the next error handler
    next(err);
};

// =============================================================================
// YJS DOCUMENT NAME / PATH TRANSLATION
// =============================================================================

/**
 * Canonical filePath <-> Yjs document name translation.
 *
 * Wire format on every layer must agree:
 *   filePath:  "/user/foo bar.md"       (absolute, unix slashes, may contain spaces / unicode)
 *   docName:   "yjs/user/foo bar.md"    (no leading slash, "yjs/" prefix; raw — no URL encoding)
 *   wsUrl:     "${WS_BASE}/yjs/user/foo bar.md" (the browser will percent-encode in transit)
 *
 * The server URL-decodes req.url before calling docNameFromUrlPath; the
 * client must NOT pre-encode the room name passed to WebsocketProvider —
 * y-websocket builds the URL itself and the browser handles encoding.
 */

const YJS_PREFIX = 'yjs';

/** Normalize a filesystem path: backslashes -> slashes, collapse duplicates,
 *  ensure absolute, strip trailing slash (except root). */
const normalizeFilePath = (filePath) => {
    if (!filePath) return '/';
    let p = String(filePath).replace(/\\/g, '/').replace(/\/+/g, '/');
    if (!p.startsWith('/')) p = '/' + p;
    if (p !== '/' && p.endsWith('/')) p = p.slice(0, -1);
    return p;
};

/** filePath -> docName.  Idempotent: if input already looks like a docName
 *  (starts with "yjs/" or "/yjs/"), it is recognized and not double-prefixed. */
const docNameFromFilePath = (filePath) => {
    const normalized = normalizeFilePath(filePath);
    if (normalized === '/') return YJS_PREFIX;
    if (normalized.startsWith(`/${YJS_PREFIX}/`)) return normalized.slice(1);
    return YJS_PREFIX + normalized;
};

/** docName -> filePath.  Inverse of docNameFromFilePath. */
const filePathFromDocName = (docName) => {
    if (!docName) return '/';
    if (docName === YJS_PREFIX) return '/';
    if (docName.startsWith(`${YJS_PREFIX}/`)) return '/' + docName.slice(YJS_PREFIX.length + 1);
    return '/' + docName.replace(/^\/+/, '');
};

/** Extract the docName from a WebSocket request URL (e.g. "/yjs/user/foo%20bar.md?token=..").
 *  Strips query string and percent-decodes so it matches docNameFromFilePath output. */
const docNameFromUrlPath = (reqUrl) => {
    const pathAndQuery = String(reqUrl || '');
    const pathOnly = pathAndQuery.split('?')[0];
    const raw = pathOnly.startsWith('/') ? pathOnly.slice(1) : pathOnly;
    try {
        return decodeURIComponent(raw);
    } catch {
        return raw;
    }
};

// =============================================================================
// YJS PERSISTENCE COORDINATOR
// =============================================================================

/**
 * Centralizes per-doc epoch (stale-batch invalidation), batched writes
 * (single timer per doc covering both Yjs snapshot AND file `updatedAt`),
 * and writeState gating so a reconnecting bindState always sees the
 * freshest MongoDB state.  Replaces the previous ad-hoc writeStatePromises
 * Map, cancelFn registry, dual 500ms/3000ms debouncers, and inline
 * compaction race.
 */
const YJS_FLUSH_DELAY_MS = parseInt(process.env.YJS_FLUSH_DELAY_MS, 10) || 500;

const makeDocState = () => ({
    epoch: 0,                  // bumped on replaceContent — old batches are discarded
    pendingUpdates: [],        // accumulated Yjs updates awaiting flush
    pendingEpoch: 0,           // epoch under which pendingUpdates were captured
    flushTimer: null,
    writePromise: null,        // in-flight writeState (or replaceContent) flush
    dirty: false,              // anything happened since last metadata touch?
    bindLoaded: false,         // true once bindState successfully loaded persisted state
                               // into the live ydoc.  Guards writeState against wiping
                               // Mongo when the WS disconnects mid-load (the classic
                               // "open 2nd window, content disappears" race).
});

class PersistenceCoordinator {
    /**
     * @param {object} opts
     * @param {object} opts.persistence  - y-mongodb-provider MongodbPersistence instance
     * @param {function} opts.touchFileMetadata - async (docName) => void
     * @param {function} [opts.onDocFlushed] - optional hook (docName, epoch) => void
     */
    constructor({ persistence, touchFileMetadata, onDocFlushed }) {
        if (!persistence) throw new Error('PersistenceCoordinator requires persistence');
        if (!touchFileMetadata) throw new Error('PersistenceCoordinator requires touchFileMetadata');
        this.persistence = persistence;
        this.touchFileMetadata = touchFileMetadata;
        this.onDocFlushed = onDocFlushed || (() => {});
        this.docs = new Map();
    }

    _state(docName) {
        let s = this.docs.get(docName);
        if (!s) {
            s = makeDocState();
            this.docs.set(docName, s);
        }
        return s;
    }

    /**
     * Called by setPersistence.bindState — loads MongoDB state into ydoc and
     * installs the update listener that schedules batched writes.  Waits for
     * any in-flight writeState so the load sees the freshest snapshot.
     */
    async bindState(docName, ydoc) {
        const state = this._state(docName);
        // A fresh bindState always re-loads — clear the prior load flag so a
        // racing writeState before this load completes can't wipe Mongo.
        state.bindLoaded = false;
        logger.info('[Yjs] bindState start', { docName });
        if (state.writePromise) {
            try { await state.writePromise; } catch { /* logged elsewhere */ }
        }

        try {
            const persistedYdoc = await this.persistence.getYDoc(docName);
            const persistedUpdate = Y.encodeStateAsUpdate(persistedYdoc);
            const loadedText = persistedYdoc.getText('content').toString();
            if (persistedUpdate.length > 0) {
                Y.applyUpdate(ydoc, persistedUpdate);
            }
            persistedYdoc.destroy();
            // Only mark loaded on success — a thrown error leaves the live ydoc
            // empty and we MUST NOT let a subsequent writeState clear Mongo.
            state.bindLoaded = true;
            logger.info('[Yjs] bindState loaded', {
                docName,
                updateBytes: persistedUpdate.length,
                textLen: loadedText.length,
            });
        } catch (error) {
            logger.error('[Yjs] bindState load failed — bindLoaded stays false', { docName, error: error.message });
        }

        ydoc.on('update', (update) => this._enqueueUpdate(docName, ydoc, update));
    }

    _enqueueUpdate(docName, ydoc, update) {
        const state = this._state(docName);
        if (state.pendingUpdates.length === 0) {
            state.pendingEpoch = state.epoch;
        }
        state.pendingUpdates.push(update);
        state.dirty = true;
        if (state.flushTimer) return;
        state.flushTimer = setTimeout(() => this._flush(docName, ydoc).catch((err) => {
            logger.error('PersistenceCoordinator flush error', { docName, error: err.message });
        }), YJS_FLUSH_DELAY_MS);
    }

    async _flush(docName, ydoc) {
        const state = this._state(docName);
        state.flushTimer = null;
        const batchEpoch = state.pendingEpoch;
        const updates = state.pendingUpdates;
        state.pendingUpdates = [];

        // Stale batch from a pre-replaceContent epoch — discard.
        if (batchEpoch !== state.epoch || updates.length === 0) {
            return;
        }

        try {
            const compacted = updates.length === 1
                ? updates[0]
                : Y.mergeUpdates(updates);
            await this.persistence.storeUpdate(docName, compacted);
        } catch (error) {
            logger.error('PersistenceCoordinator storeUpdate failed', { docName, error: error.message });
        }

        if (state.dirty) {
            state.dirty = false;
            try {
                await this.touchFileMetadata(docName);
            } catch (error) {
                logger.error('PersistenceCoordinator touchFileMetadata failed', { docName, error: error.message });
            }
        }

        this.onDocFlushed(docName, batchEpoch);
    }

    /**
     * Called by setPersistence.writeState — runs when the last client
     * disconnects.  Serialized per-doc via state.writePromise so concurrent
     * bindState calls wait for the snapshot to commit before reading.
     */
    async writeState(docName, ydoc) {
        const state = this._state(docName);
        const work = (async () => {
            if (state.flushTimer) {
                clearTimeout(state.flushTimer);
                state.flushTimer = null;
            }
            state.pendingUpdates = [];

            // CRITICAL #1: if bindState never finished loading persisted state
            // into this ydoc, do not touch Mongo.  Otherwise a transient
            // disconnect mid-load (StrictMode unmount, brief network blip, 2nd
            // window race, failed Mongo read) triggers conns.size === 0 →
            // writeState → we would clearDocument on an EMPTY ydoc and
            // permanently wipe the file.
            if (!state.bindLoaded) {
                logger.warn('[Yjs] writeState SKIPPED: bindState did not complete (preserving Mongo state)', { docName });
                return;
            }

            try {
                const fullState = Y.encodeStateAsUpdate(ydoc);
                const liveText = ydoc.getText('content').toString();

                // CRITICAL #2: never clearDocument when the in-memory ydoc is
                // empty.  If we did, an empty ydoc (from any cause: failed
                // sync, GC race, multi-instance split-brain stale copy, an
                // unexpected Yjs edge case) would wipe persisted content.
                // Lengths <= 2 are the Yjs "empty doc" encoding.
                if (fullState.length <= 2 || liveText.length === 0) {
                    logger.warn('[Yjs] writeState SKIPPED: live ydoc is empty, refusing to clear Mongo', {
                        docName,
                        fullStateBytes: fullState.length,
                        liveTextLen: liveText.length,
                    });
                    return;
                }

                logger.info('[Yjs] writeState flushing', {
                    docName,
                    fullStateBytes: fullState.length,
                    liveTextLen: liveText.length,
                });
                await this.persistence.clearDocument(docName);
                await this.persistence.storeUpdate(docName, fullState);
                if (state.dirty) {
                    state.dirty = false;
                    try { await this.touchFileMetadata(docName); } catch (e) {
                        logger.error('writeState touchFileMetadata failed', { docName, error: e.message });
                    }
                }
            } catch (error) {
                logger.error('PersistenceCoordinator writeState failed', { docName, error: error.message });
            }
        })();
        state.writePromise = work;
        try {
            await work;
        } finally {
            if (state.writePromise === work) state.writePromise = null;
        }
    }

    /**
     * Atomically replace the content of a Yjs document.  Used by file
     * create / overwrite / delete operations.  Epoch is bumped FIRST so any
     * in-flight batched write of pre-replace updates is dropped on flush.
     */
    async replaceContent(docName, content, { liveDoc } = {}) {
        const state = this._state(docName);
        state.epoch += 1;
        state.pendingUpdates = [];
        if (state.flushTimer) {
            clearTimeout(state.flushTimer);
            state.flushTimer = null;
        }

        if (state.writePromise) {
            try { await state.writePromise; } catch { /* logged */ }
        }

        if (liveDoc) {
            liveDoc.transact(() => {
                const ytext = liveDoc.getText('content');
                ytext.delete(0, ytext.length);
                if (content) ytext.insert(0, content);
            });
            return;
        }

        const work = (async () => {
            try {
                await this.persistence.clearDocument(docName);
                if (content) {
                    const ydoc = new Y.Doc();
                    ydoc.getText('content').insert(0, content);
                    await this.persistence.storeUpdate(docName, Y.encodeStateAsUpdate(ydoc));
                    ydoc.destroy();
                }
                try { await this.touchFileMetadata(docName); } catch (e) {
                    logger.error('replaceContent touchFileMetadata failed', { docName, error: e.message });
                }
            } catch (error) {
                logger.error('PersistenceCoordinator replaceContent failed', { docName, error: error.message });
                throw error;
            }
        })();
        state.writePromise = work;
        try {
            await work;
        } finally {
            if (state.writePromise === work) state.writePromise = null;
        }
    }

    /** Flush all pending writes and clear all per-doc state.  Call on shutdown. */
    async shutdown() {
        const promises = [];
        for (const [, state] of this.docs) {
            if (state.flushTimer) {
                clearTimeout(state.flushTimer);
                state.flushTimer = null;
            }
            if (state.writePromise) promises.push(state.writePromise.catch(() => {}));
            state.pendingUpdates = [];
        }
        await Promise.all(promises);
        this.docs.clear();
    }
}

// =============================================================================
// YJS REDIS ADAPTER FOR HORIZONTAL SCALING
// =============================================================================

/**
 * Redis Pub/Sub Adapter for Yjs Collaborative Editing
 * 
 * Provides horizontal scaling capabilities for Yjs documents across multiple server instances
 * using Redis pub/sub messaging. This enables real-time synchronization of document updates
 * between different server instances in a multi-server deployment.
 * 
 * Features:
 * - Redis pub/sub for cross-server document synchronization
 * - Integration with existing MongoDB persistence
 * - Connection management and error handling
 * - Document-specific channels for efficient message routing
 * - Graceful degradation when Redis is unavailable
 */
class YjsRedisAdapter {
    constructor(redisClient, options = {}) {
        this.redisClient = redisClient;
        this.persistence = null;
        this.documents = new Map(); // docName -> PersistenceDoc
        this.isEnabled = options.enabled !== false;
        this.prefix = options.prefix || 'yjs:';

        this.config = {
            channelPrefix: options.channelPrefix || 'yjs-doc:',
            redisOpts: options.redisOpts,
            ...options
        };

        this.isInitialized = false;
        this.isConnected = false;
    }

    getRedisOptions() {
        if (this.config.redisOpts) {
            return this.config.redisOpts;
        }

        const clientOptions = this.redisClient?.options ?? {};
        const {url, socket = {}, username, password, database} = clientOptions;

        if (url) {
            return {url};
        }

        const redisOpts = {};

        if (socket.host) {
            redisOpts.host = socket.host;
        }

        if (socket.port) {
            redisOpts.port = socket.port;
        }

        if (username) {
            redisOpts.username = username;
        }

        if (password) {
            redisOpts.password = password;
        }

        if (typeof database === 'number') {
            redisOpts.db = database;
        }

        return redisOpts;
    }

    async initialize() {
        if (this.isInitialized) {
            logger.warn('[YjsRedisAdapter] Already initialized');
            return;
        }

        if (!this.isEnabled) {
            logger.info('[YjsRedisAdapter] Redis pub/sub disabled');
            return;
        }

        try {
            const redisOpts = this.getRedisOptions();
            this.persistence = new RedisPersistence({redisOpts});
            this.isInitialized = true;
            this.isConnected = true;
            logger.info('[YjsRedisAdapter] Redis persistence initialized for Yjs scaling');
        } catch (error) {
            logger.error('[YjsRedisAdapter] Failed to initialize Redis persistence:', {
                error: error.message,
                stack: error.stack
            });
            await this.cleanup();
            throw error;
        }
    }

    async getAdapter(docName) {
        if (!this.isEnabled || !this.isInitialized || !this.persistence) {
            return null;
        }

        return this.documents.get(docName) ?? null;
    }

    async removeAdapter(docName) {
        const adapter = this.documents.get(docName);
        if (!adapter) {
            return;
        }

        try {
            if (typeof adapter.destroy === 'function') {
                await adapter.destroy();
            }
        } catch (error) {
            logger.error('[YjsRedisAdapter] Error removing adapter:', {
                docName,
                error: error.message
            });
        } finally {
            this.documents.delete(docName);
        }
    }

    async bindDocument(docName, ydoc) {
        if (!this.isEnabled || !this.isInitialized || !this.persistence) {
            return null;
        }

        try {
            const persistenceDoc = this.persistence.bindState(docName, ydoc);
            this.documents.set(docName, persistenceDoc);
            return persistenceDoc;
        } catch (error) {
            logger.error('[YjsRedisAdapter] Failed to bind document to Redis persistence:', {
                docName,
                error: error.message
            });
            return null;
        }
    }

    async unbindDocument(docName, ydoc) {
        if (!this.documents.has(docName)) {
            return;
        }

        try {
            await this.removeAdapter(docName);
            if (this.persistence && typeof this.persistence.closeDoc === 'function') {
                await this.persistence.closeDoc(docName);
            }
        } catch (error) {
            logger.error('[YjsRedisAdapter] Error unbinding document:', {
                docName,
                hasYDoc: !!ydoc,
                error: error.message
            });
        }
    }

    getStats() {
        return {
            isEnabled: this.isEnabled,
            isInitialized: this.isInitialized,
            isConnected: this.isConnected && !!this.persistence,
            activeAdapters: this.documents.size,
            reconnectAttempts: 0,
            maxReconnectAttempts: 0,
            documents: Array.from(this.documents.keys())
        };
    }

    async healthCheck() {
        if (!this.isEnabled) {
            return {status: 'disabled', message: 'Redis pub/sub is disabled'};
        }

        if (!this.isInitialized || !this.persistence) {
            return {status: 'not_initialized', message: 'Redis persistence not initialized'};
        }

        try {
            if (typeof this.redisClient?.ping === 'function') {
                await this.redisClient.ping();
            }

            return {
                status: 'healthy',
                message: 'Redis persistence is operational',
                stats: this.getStats()
            };
        } catch (error) {
            return {
                status: 'unhealthy',
                message: `Redis health check failed: ${error.message}`,
                error: error.message
            };
        }
    }

    async cleanup() {
        const adapters = Array.from(this.documents.entries());
        for (const [docName, adapter] of adapters) {
            try {
                if (adapter && typeof adapter.destroy === 'function') {
                    await adapter.destroy();
                }
            } catch (error) {
                logger.warn(`[YjsRedisAdapter] Error cleaning up adapter for ${docName}:`, error.message);
            }
        }

        this.documents.clear();

        if (this.persistence) {
            try {
                await this.persistence.destroy();
            } catch (error) {
                logger.warn('[YjsRedisAdapter] Error destroying Redis persistence:', error.message);
            }
        }

        this.persistence = null;
        this.isInitialized = false;
        this.isConnected = false;
    }

    async destroy() {
        await this.cleanup();
    }
}

// =============================================================================
// YJS SERVICE FOR COLLABORATIVE EDITING
// =============================================================================

/**
 * Yjs Service for collaborative text editing with MongoDB persistence and Redis scaling
 * Manages document lifecycle, content synchronization, and cross-server communication
 */
class YjsService {
    constructor() {
        this.persistence = null;
        this.redisAdapter = null;
        this.isInitialized = false;
        this.documents = new Map(); // Cache for persistent Yjs documents
        this.wsDocsMap = null; // Reference to @y/websocket-server's in-memory docs Map
        this.coordinator = null; // PersistenceCoordinator (wired from server.js)
        
        this.config = {
            collectionName: process.env.YJS_COLLECTION_NAME,
            flushSize: parseInt(process.env.YJS_FLUSH_SIZE),
            debounceDelay: parseInt(process.env.YJS_DEBOUNCE_DELAY),
            // Redis pub/sub configuration
            redisEnabled: process.env.YJS_REDIS_ENABLED === 'true',
            redisPrefix: process.env.YJS_REDIS_PREFIX,
            redisChannelPrefix: process.env.YJS_REDIS_CHANNEL_PREFIX
        };
    }

    /**
     * Validate required configuration values
     */
    validateConfig() {
        const requiredFields = [
            'collectionName',
            'flushSize',
            'debounceDelay',
            'redisPrefix',
            'redisChannelPrefix'
        ];

        const missingFields = [];
        
        for (const field of requiredFields) {
            if (!this.config[field] && this.config[field] !== 0) {
                missingFields.push(`YJS_${field.replace(/([A-Z])/g, '_$1').toUpperCase()}`);
            }
        }

        // Check for invalid numeric values
        if (isNaN(this.config.flushSize) || this.config.flushSize <= 0) {
            missingFields.push('YJS_FLUSH_SIZE (must be a positive integer)');
        }
        
        if (isNaN(this.config.debounceDelay) || this.config.debounceDelay < 0) {
            missingFields.push('YJS_DEBOUNCE_DELAY (must be a non-negative integer)');
        }

        if (missingFields.length > 0) {
            throw new Error(`Missing or invalid Yjs configuration environment variables: ${missingFields.join(', ')}. Please check your .env file.`);
        }
    }

    /**
     * Initialize the Yjs persistence layer with Redis pub/sub scaling
     */
    async initialize() {
        if (this.isInitialized) {
            return this.persistence;
        }

        try {
            // Validate configuration when initializing
            this.validateConfig();
            
            // Get existing Mongoose connection to reuse it
            if (mongoose.connection.readyState === 1) {
                // Use existing Mongoose connection for Y-MongoDB provider
                const mongoClient = mongoose.connection.getClient();
                const db = mongoose.connection.db;
                
                this.persistence = new MongodbPersistence({
                    client: mongoClient,
                    db: db
                }, {
                    collectionName: this.config.collectionName,
                    flushSize: this.config.flushSize,
                    multipleCollections: false
                });
                
                logger.info('YJS: Using existing Mongoose connection', {
                    database: db.databaseName,
                    collection: this.config.collectionName
                });
            } else {
                // Fallback to connection string if Mongoose not connected
                logger.info('YJS: Using connection string for MongoDB persistence');
                this.persistence = new MongodbPersistence(process.env.MONGODB_URI, {
                    collectionName: this.config.collectionName,
                    flushSize: this.config.flushSize,
                    multipleCollections: false
                });
            }

            // Initialize Redis pub/sub adapter for scaling
            if (this.config.redisEnabled) {
                try {
                    this.redisAdapter = new YjsRedisAdapter(redisClient, {
                        enabled: this.config.redisEnabled,
                        prefix: this.config.redisPrefix,
                        channelPrefix: this.config.redisChannelPrefix
                    });

                    await this.redisAdapter.initialize();
                    
                    logger.info('YjsService initialized with Redis pub/sub scaling', {
                        collectionName: this.config.collectionName,
                        flushSize: this.config.flushSize,
                        redisEnabled: true
                    });
                } catch (redisError) {
                    logger.warn('Redis pub/sub initialization failed, continuing with MongoDB-only persistence', {
                        error: redisError.message
                    });
                    this.redisAdapter = null;
                }
            } else {
                logger.info('Redis pub/sub scaling disabled');
            }

            this.isInitialized = true;
            
            logger.info('YjsService initialized', {
                collectionName: this.config.collectionName,
                flushSize: this.config.flushSize,
                redisEnabled: !!this.redisAdapter
            });

            return this.persistence;
        } catch (error) {
            logger.error('Failed to initialize YjsService', { error: error.message });
            throw error;
        }
    }

    /**
     * Get the Yjs document name for a file path.
     * Delegates to the canonical helper so client + server + WS URL stay aligned.
     */
    getDocumentName(filePath) {
        return docNameFromFilePath(filePath);
    }



    /**
     * Get existing Yjs document (pure retrieval, no modification)
     * Standard pattern: documents should already exist from create/move/rename/copy operations
     */
    async getDocument(filePath) {
        if (!this.persistence) {
            throw new Error('YjsService not initialized');
        }

        const docName = this.getDocumentName(filePath);
        
        // Always get fresh document from persistence to ensure latest content
        // This is critical for version saving to capture current collaborative edits
        const ydoc = await this.persistence.getYDoc(docName);
        
        // Update cache with fresh document
        this.documents.set(docName, ydoc);
        
        return ydoc;
    }

    /**
     * Get text content from a Yjs document (returns empty string if no content)
     */
    async getTextContent(filePath) {
        try {
            if (!filePath) {
                throw new Error('File path is required to get text content');
            }
            
            const ydoc = await this.getDocument(filePath);
            const content = ydoc.getText('content').toString();
            
            return content;
        } catch (error) {
            logger.error('Failed to get text content:', { filePath, error: error.message });
            throw error;
        }
    }

    /**
     * Get document metadata including last modified time from Yjs document
     * Enhanced to check MongoDB Yjs persistence for more accurate timestamps
     */
    async getDocumentMetadata(filePath) {
        try {
            if (!filePath) {
                throw new Error('File path is required to get document metadata');
            }

            const docName = this.getDocumentName(filePath);
            const ydoc = await this.getDocument(filePath);
            const ytext = ydoc.getText('content');
            const content = ytext.toString();
            const hasContent = content.length > 0;

            // Check MongoDB Yjs collection for last modified timestamp
            let lastModified = new Date();
            let hasPersistedData = false;

            if (this.persistence && hasContent) {
                try {
                    // Access MongoDB Yjs collection directly to get document metadata
                    if (mongoose.connection.readyState === 1) {
                        const db = mongoose.connection.db;
                        const yjsCollection = db.collection(this.config.collectionName);
                        
                        // Find the most recent document entry for this document
                        const latestEntry = await yjsCollection
                            .findOne(
                                { docName: docName },
                                { sort: { clock: -1 } }
                            );

                        if (latestEntry && latestEntry._id) {
                            // Use the MongoDB ObjectId timestamp as the last modified time
                            lastModified = latestEntry._id.getTimestamp();
                            hasPersistedData = true;
                        }
                    }
                } catch (persistenceError) {
                    logger.debug('Could not get Yjs persistence timestamp:', {
                        filePath,
                        docName,
                        error: persistenceError.message
                    });
                }
            }

            return {
                filePath,
                docName,
                hasContent,
                contentLength: content.length,
                lastModified,
                hasPersistedData,
                isActive: this.documents.has(docName)
            };

        } catch (error) {
            logger.error('Failed to get document metadata:', { filePath, error: error.message });
            return {
                filePath,
                hasContent: false,
                contentLength: 0,
                lastModified: new Date(),
                hasPersistedData: false,
                isActive: false
            };
        }
    }

    /**
     * Get bulk document metadata for statistics - simplified version
     * Returns which text files actually have content (were edited)
     */
    async getBulkDocumentMetadata(filePaths) {
        try {
            if (!Array.isArray(filePaths) || filePaths.length === 0) {
                return [];
            }

            const metadataResults = await Promise.allSettled(
                filePaths.map(filePath => this.getDocumentMetadata(filePath))
            );

            return metadataResults
                .filter(result => result.status === 'fulfilled')
                .map(result => result.value);

        } catch (error) {
            logger.error('Failed to get bulk document metadata:', { 
                fileCount: filePaths?.length || 0, 
                error: error.message 
            });
            return [];
        }
    }



    /**
     * Initialize or replace a Yjs document with new content.
     * Used for file creation (new upload) and file overwrite (re-upload).
     *
     * Delegates to PersistenceCoordinator.replaceContent which:
     *   - Bumps the per-doc epoch so any in-flight batched write of pre-replace
     *     updates is discarded when its flush timer fires (no manual cancelFn).
     *   - If a live wsDoc exists, applies the change as a transaction so
     *     connected clients receive the delta via the sync protocol — no
     *     eviction, no auto-reconnect race with stale client state.
     *   - Otherwise clears MongoDB and writes the new content directly.
     */
    async initializeTextContent(filePath, initialContent) {
        const docName = this.getDocumentName(filePath);

        // Drop our own cache entry — it's about to be stale either way.
        const cachedDoc = this.documents.get(docName);
        const liveDoc = this.wsDocsMap?.get(docName) ?? null;
        if (cachedDoc && cachedDoc !== liveDoc) {
            cachedDoc.destroy();
        }
        this.documents.delete(docName);

        if (!this.coordinator) {
            throw new Error('YjsService.initializeTextContent called before coordinator was wired');
        }

        await this.coordinator.replaceContent(docName, initialContent || '', { liveDoc });

        logger.info('Yjs document content replaced', {
            filePath,
            docName,
            contentLength: initialContent?.length || 0,
            mode: liveDoc ? 'live-transaction' : 'mongo-direct',
        });
    }

    /**
     * Delete a Yjs document — clears MongoDB and (if connected clients exist)
     * pushes the empty state to them via a live transaction.  Same coordinator
     * path as initializeTextContent('') so epoch invalidation prevents stale
     * writes after the delete.
     */
    async deleteDocument(filePath) {
        try {
            const docName = this.getDocumentName(filePath);
            const cachedDoc = this.documents.get(docName);
            const liveDoc = this.wsDocsMap?.get(docName) ?? null;
            if (cachedDoc && cachedDoc !== liveDoc) {
                cachedDoc.destroy();
            }
            this.documents.delete(docName);

            if (this.redisAdapter) {
                try { await this.redisAdapter.removeAdapter(docName); }
                catch (redisErr) {
                    logger.debug('Redis adapter cleanup during delete (non-fatal):', { docName, error: redisErr.message });
                }
            }

            if (this.coordinator) {
                await this.coordinator.replaceContent(docName, '', { liveDoc });
            }

            logger.info('Yjs document deleted', { filePath, docName });
        } catch (error) {
            logger.error('Failed to delete Yjs document:', { filePath, error: error.message });
            // Don't throw — deletion should not fail the parent operation
        }
    }

    /**
     * Copy Yjs document from one path to another
     * Creates a new document with the same content at the new path
     */
    async copyDocument(fromPath, toPath) {
        try {
            if (!fromPath || !toPath) {
                throw new Error('Both source and destination paths are required');
            }
            
            if (fromPath === toPath) {
                logger.warn('YJS DOCUMENT COPY: Source and destination are identical, skipping', {
                    path: fromPath
                });
                return;
            }
            
            // Get source document and create new target document
            const sourceDoc = await this.getDocument(fromPath);
            const targetDoc = await this.getDocument(toPath);
            
            // Copy content from source to target document
            const sourceText = sourceDoc.getText('content');
            const targetText = targetDoc.getText('content');
            const sourceContent = sourceText.toString();
            
            if (sourceContent && targetText.toString().length === 0) {
                targetText.insert(0, sourceContent);
                
                // Force persistence of the target document
                if (this.persistence) {
                    const targetDocName = this.getDocumentName(toPath);
                    await this.persistence.storeUpdate(targetDocName, Y.encodeStateAsUpdate(targetDoc));
                }
            }
        } catch (error) {
            logger.error('Failed to copy YJS document:', {
                fromPath,
                toPath,
                error: error.message
            });
            throw error;
        }
    }

    /**
     * Move Yjs document from one path to another
     * Updates the document path in the persistence layer
     */
    async moveDocument(fromPath, toPath) {
        try {
            if (!fromPath || !toPath) {
                throw new Error('Both source and destination paths are required');
            }
            
            const sourceDocName = this.getDocumentName(fromPath);
            const targetDocName = this.getDocumentName(toPath);
            
            // Skip if source and target are the same
            if (sourceDocName === targetDocName) {
                return;
            }
            
            // Ensure document is synchronized before move operation
            // Note: The WebSocket server handles persistence automatically
            // Add buffer to allow any pending operations and persistence to complete
            await new Promise(resolve => setTimeout(resolve, 250));
            
            // Get source document
            const sourceDoc = await this.getDocument(fromPath);
            const sourceText = sourceDoc.getText('content');
            const sourceContent = sourceText.toString();
            
            // Create target document
            const targetDoc = await this.getDocument(toPath);
            const targetText = targetDoc.getText('content');
            const existingTargetContent = targetText.toString();
            
            // Only copy content if target is empty to avoid overwriting
            if (sourceContent && existingTargetContent.length === 0) {
                targetText.insert(0, sourceContent);
                
                // Verify content was copied correctly
                const copiedContent = targetText.toString();
                if (copiedContent !== sourceContent) {
                    logger.error('Content copy verification failed during move:', {
                        fromPath,
                        toPath,
                        sourceLength: sourceContent.length,
                        targetLength: copiedContent.length
                    });
                }
                
                // Force persistence of the target document
                if (this.persistence) {
                    await this.persistence.storeUpdate(targetDocName, Y.encodeStateAsUpdate(targetDoc));
                }
            }
            
            // Clean up the source document from both cache and persistence
            this.documents.delete(sourceDocName);
            
            // Clean up source document from MongoDB persistence
            if (this.persistence) {
                try {
                    await this.persistence.clearDocument(sourceDocName);
                } catch (persistenceError) {
                    logger.warn('Failed to clear source document from persistence:', {
                        sourceDocName,
                        error: persistenceError.message
                    });
                }
            }
        } catch (error) {
            logger.error('Failed to move YJS document:', {
                fromPath,
                toPath,
                error: error.message
            });
            throw error;
        }
    }

    /**
     * Bind Redis adapter to a Yjs document for cross-server synchronization
     */
    async bindRedisAdapter(docName, ydoc) {
        if (!this.redisAdapter) {
            return null; // No Redis adapter available
        }

        try {
            return await this.redisAdapter.bindDocument(docName, ydoc);
        } catch (error) {
            logger.error('Failed to bind Redis adapter to document', {
                docName,
                error: error.message
            });
            return null;
        }
    }

    /**
     * Unbind Redis adapter from a Yjs document
     */
    async unbindRedisAdapter(docName, ydoc) {
        if (!this.redisAdapter) {
            return;
        }

        try {
            await this.redisAdapter.unbindDocument(docName, ydoc);
        } catch (error) {
            logger.error('Failed to unbind Redis adapter from document', {
                docName,
                error: error.message
            });
        }
    }

    /**
     * Get Redis adapter statistics
     */
    getRedisStats() {
        if (!this.redisAdapter) {
            return { enabled: false, message: 'Redis adapter not initialized' };
        }

        return this.redisAdapter.getStats();
    }

    /**
     * Health check for Redis adapter
     */
    async redisHealthCheck() {
        if (!this.redisAdapter) {
            return { status: 'disabled', message: 'Redis adapter not initialized' };
        }

        return await this.redisAdapter.healthCheck();
    }

    /**
     * Provide the @y/websocket-server `docs` Map so that
     * deleteDocument / initializeTextContent can apply transactions to
     * the in-memory WSSharedDoc when clients are connected.
     */
    setWsDocsMap(docsMap) {
        this.wsDocsMap = docsMap;
        logger.info('YjsService: WebSocket docs map reference set');
    }

    /**
     * Wire the PersistenceCoordinator (created in server.js where the
     * @y/websocket-server `setPersistence` callbacks are registered).
     * YjsService delegates all replace-content / delete flows to it so a
     * single source of truth owns batched writes, epoch invalidation, and
     * writeState gating.
     */
    setCoordinator(coordinator) {
        this.coordinator = coordinator;
        logger.info('YjsService: persistence coordinator wired');
    }

    /**
     * Get persistence instance for WebSocket server setup
     */
    getPersistence() {
        return this.persistence;
    }

    /**
     * Get Redis adapter instance
     */
    getRedisAdapter() {
        return this.redisAdapter;
    }

    /**
     * Cleanup resources
     */
    async destroy() {
        // Clear document cache
        if (this.documents) {
            this.documents.clear();
            logger.debug('Yjs document cache cleared');
        }

        // Cleanup Redis adapter
        if (this.redisAdapter) {
            try {
                await this.redisAdapter.destroy();
                logger.info('Redis adapter cleaned up');
            } catch (error) {
                logger.warn('Error cleaning up Redis adapter:', error.message);
            }
            this.redisAdapter = null;
        }

        if (this.persistence) {
            // MongodbPersistence doesn't have explicit cleanup methods
            // Just clear the reference
            this.persistence = null;
        }
        
        this.isInitialized = false;
        logger.info('YjsService destroyed');
    }
}

/**
 * File Notification Service
 * Handles real-time notifications for file operations (separate from Yjs collaboration)
 * Integrated into file middleware for better architectural organization
 */
class FileNotificationService {
    constructor() {
        this.wss = null;
        this.connections = new Map(); // userId -> Set of WebSocket connections
        this.userSessions = new Map(); // userId -> user info
    }

    /**
     * Initialize notification service (without creating a separate server)
     * Connections will be routed from the main WebSocket server
     */
    initialize() {
        // No separate WebSocket server needed - connections routed from main server
        logger.info('🔔 File notification service initialized on /notifications path');
    }

    /**
     * Handle new WebSocket connection
     */
    async handleConnection(ws, req) {
        try {
            // JWT is available via top-level import

            // Extract token from query parameters or headers
            const url = new URL(req.url, `http://${req.headers.host}`);
            const token = url.searchParams.get('token') || req.headers.authorization?.replace('Bearer ', '');

            if (!token) {
                ws.close(1008, 'Authentication token required');
                return;
            }

            // Verify JWT token
            const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
            const userId = decoded.id;

            // Store connection
            if (!this.connections.has(userId)) {
                this.connections.set(userId, new Set());
            }
            this.connections.get(userId).add(ws);

            // Store user session info
            this.userSessions.set(userId, {
                id: userId,
                username: decoded.username,
                connectedAt: new Date()
            });

            logger.debug('📱 File notification WebSocket connected', { userId, username: decoded.username });

            // Handle connection close
            ws.on('close', () => {
                this.removeConnection(userId, ws);
            });

            // Handle incoming messages (for subscriptions, etc.)
            ws.on('message', (data) => {
                this.handleMessage(userId, ws, data);
            });

            // Send connection confirmation
            this.sendToConnection(ws, {
                type: 'connection:established',
                data: { userId, timestamp: new Date().toISOString() }
            });

        } catch (error) {
            if (error.name === 'JsonWebTokenError') {
                logger.warn('Invalid JWT token for file notification WebSocket', { error: error.message });
                ws.close(1008, 'Invalid authentication token');
            } else {
                logger.error('File notification WebSocket authentication failed:', error);
                ws.close(1008, 'Authentication failed');
            }
        }
    }

    /**
     * Handle incoming WebSocket messages
     */
    handleMessage(userId, ws, data) {
        try {
            const message = JSON.parse(data);
            
            switch (message.type) {
                case 'ping':
                    this.sendToConnection(ws, { type: 'pong', timestamp: new Date().toISOString() });
                    break;
                default:
                    logger.warn('Unknown message type:', message.type);
            }
        } catch (error) {
            logger.error('Error handling WebSocket message:', error);
        }
    }

    /**
     * Remove connection when client disconnects
     */
    removeConnection(userId, ws) {
        const userConnections = this.connections.get(userId);
        if (userConnections) {
            userConnections.delete(ws);
            if (userConnections.size === 0) {
                this.connections.delete(userId);
                this.userSessions.delete(userId);
            }
        }
        logger.debug('📱 File notification WebSocket disconnected', { userId });
    }



    /**
     * Send notification to specific user
     */
    sendToUser(userId, notification) {
        const userConnections = this.connections.get(userId);
        if (userConnections && userConnections.size > 0) {
            userConnections.forEach(ws => {
                if (ws.readyState === WebSocket.OPEN) {
                    this.sendToConnection(ws, notification);
                }
            });
            return true;
        }
        return false;
    }

    /**
     * Send notification to multiple users
     */
    sendToUsers(userIds, notification) {
        const sentCount = userIds.reduce((count, userId) => {
            return this.sendToUser(userId, notification) ? count + 1 : count;
        }, 0);
        
        logger.debug('📤 File notification sent', { 
            type: notification.type, 
            totalUsers: userIds.length, 
            connectedUsers: sentCount 
        });
        
        return sentCount;
    }

    /**
     * Send notification to specific WebSocket connection
     */
    sendToConnection(ws, notification) {
        try {
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                    ...notification,
                    timestamp: notification.timestamp || new Date().toISOString()
                }));
            }
        } catch (error) {
            logger.error('Error sending WebSocket notification:', error);
        }
    }

    /**
     * Broadcast file operation notification to all users with access
     * @param {string} eventType - The type of event (FILE_EVENTS constant)
     * @param {object} eventData - Event data to send
     * @param {string|array} filePathOrUsers - Either a filePath to look up users, or array of user IDs to notify directly
     */
    async broadcastFileEvent(eventType, eventData, filePathOrUsers) {
        try {
            let affectedUsers = [];
            let lookupPath = null;

            // Determine if we're given user IDs directly or need to look up the file
            if (Array.isArray(filePathOrUsers)) {
                // Direct user IDs provided (for delete/rename where file may not exist)
                affectedUsers = filePathOrUsers;
            } else {
                // File path provided - look up the file to get users
                lookupPath = filePathOrUsers;
                const file = await File.findOne({ filePath: lookupPath })
                    .populate('owner', '_id username')
                    .populate('permissions.read', '_id username')
                    .populate('permissions.write', '_id username');

                if (!file) {
                    logger.warn('File not found for notification broadcast:', lookupPath);
                    return 0;
                }

                // Collect all user IDs with access
                const userSet = new Set();
                userSet.add(file.owner._id.toString());
                
                file.permissions.read.forEach(user => userSet.add(user._id.toString()));
                file.permissions.write.forEach(user => userSet.add(user._id.toString()));
                
                affectedUsers = Array.from(userSet);
            }

            // Create notification payload
            const notification = {
                type: eventType,
                data: eventData
            };

            // Send to all affected users
            const sentCount = this.sendToUsers(affectedUsers, notification);
            
            logger.info('📢 File event broadcasted', {
                eventType,
                filePath: eventData.filePath || eventData.oldFilePath || lookupPath,
                affectedUsers: affectedUsers.length,
                connectedUsers: sentCount
            });

            return sentCount;

        } catch (error) {
            logger.error('Error broadcasting file event:', error);
            return 0;
        }
    }

    /**
     * Shutdown the notification service
     */
    shutdown() {
        this.connections.clear();
        this.userSessions.clear();
        logger.info('🔔 File notification service shut down');
    }
}

// Create singleton instance
let fileNotificationService = null;

const getFileNotificationService = () => {
    if (!fileNotificationService) {
        fileNotificationService = new FileNotificationService();
    }
    return fileNotificationService;
};

// Create singleton instance only when explicitly needed
let yjsService = null;

const getYjsService = () => {
    if (!yjsService) {
        yjsService = new YjsService();
    }
    return yjsService;
};

// Graceful shutdown handling
const gracefulShutdown = async () => {
    if (yjsService) {
        logger.info('Graceful shutdown initiated, cleaning up Yjs service...');
        await yjsService.destroy();
        yjsService = null;
    }
};

// Only register shutdown handlers once
if (!process.listenerCount('SIGTERM')) {
    process.on('SIGTERM', gracefulShutdown);
}

if (!process.listenerCount('SIGINT')) {
    process.on('SIGINT', gracefulShutdown);
}

export {
    // Core upload functionality
    upload,

    // Compression/decompression functionality
    compressFileBuffer,
    decompressFileBuffer,
    shouldCompressFile,
    getCompressionStats,
    COMPRESSION_CONFIG,

    // Error handling
    handleFileErrors,

    // Yjs collaborative editing functionality
    YjsRedisAdapter,
    YjsService,
    getYjsService,
    PersistenceCoordinator,
    docNameFromFilePath,
    filePathFromDocName,
    docNameFromUrlPath,
    normalizeFilePath,

    // File notification functionality
    FileNotificationService,
    getFileNotificationService,
    
    // File event constants
    FILE_EVENTS
};
