/**
 * Server Application Class
 * Provides a complete server instance with database connections, middleware and routes.
 */

import express from 'express';
import path from 'node:path';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import http from 'node:http';
import WebSocket from 'ws';
import {setupWSConnection, setPersistence, docs} from '@y/websocket-server/utils';

// Load environment variables FIRST before importing other local modules
dotenv.config({path: path.resolve(process.cwd(), '.env')});

const loggerModule = await import('./utils/app.logger.js');
const logger = loggerModule.default ?? loggerModule.logger ?? loggerModule;

const dbModule = await import('./config/db.js');
const {connectDB} = dbModule;

const errorHandlerModule = await import('./middleware/error.middleware.js');
const errorHandler = errorHandlerModule.default ?? errorHandlerModule.errorHandler ?? errorHandlerModule;

const appMiddleware = await import('./middleware/app.middleware.js');
const appController = await import('./controllers/app.controller.js');

const cacheMiddleware = await import('./middleware/cache.middleware.js');
const {noCacheResponse} = cacheMiddleware;

const cacheControllerModule = await import('./controllers/cache.controller.js');
const {cleanupService} = cacheControllerModule;

const fileMiddleware = await import('./middleware/file.middleware.js');
const {
    getFileNotificationService,
    getYjsService,
    PersistenceCoordinator,
    docNameFromUrlPath,
    filePathFromDocName,
} = fileMiddleware;
const notificationService = getFileNotificationService();

const {redisClient} = appMiddleware;

/**
 * Server class that encapsulates the Express application
 */
class Server {
    /**
     * Creates a new Server instance
     * @param {Object} options - Server configuration options
     * @param {string} options.envPath - Path to .env file
     */

    constructor(options = {}) {
        // Load environment variables
        this.loadEnvironment(options.envPath);

        // Create Express app
        this.app = express();
        this.app.set('trust proxy', 1);

        // Create HTTP server (shared with Express app)
        this.httpServer = http.createServer(this.app);

        // Initialize server and connections
        this.server = null;
        this.isInitialized = false;

        // Store configuration
        this.config = {
            port: process.env.PORT,
            environment: process.env.NODE_ENV,
            mongoUri: process.env.MONGODB_URI,
            cacheEnabled: process.env.CACHE_ENABLED !== 'false',
            allowedOrigins: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : []
        };

        // Debug log to test if debug level is working
        logger.debug('🔧 Server constructor initialized', {
            logLevel: process.env.LOG_LEVEL,
            environment: this.config.environment,
            port: this.config.port
        });

        // Register error handlers for uncaught exceptions
        this.registerProcessHandlers();
    }

    /**
     * Load environment variables from .env file
     * @param {string} envPath - Path to .env file
     */
    loadEnvironment(envPath) {
        // Environment variables are already loaded at the top of this file
        // This method now just handles alternative env paths for testing
        if (envPath && envPath !== path.resolve(process.cwd(), '.env')) {
            const envFile = path.resolve(envPath);
            dotenv.config({path: envFile});

            // Debug log to check if LOG_LEVEL is properly loaded
            logger.debug('🔧 ENV DEBUG - LOG_LEVEL after custom dotenv.config():', process.env.LOG_LEVEL);
            logger.debug('🔧 ENV DEBUG - NODE_ENV:', process.env.NODE_ENV);
        }

        this.validateEnvironment();
    }

    /**
     * Validate that all required environment variables are set
     */
    validateEnvironment() {
        const requiredEnvVars = [
            'PORT',
            'NODE_ENV',
            'MONGODB_URI',
            'ALLOWED_ORIGINS',
            'ACCESS_TOKEN_SECRET',
            'REFRESH_TOKEN_SECRET',
            'ACCESS_TOKEN_EXPIRY',
            'REFRESH_TOKEN_EXPIRY'
        ];

        const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);
        if (missingEnvVars.length > 0) {
            logger.error('Missing required environment variables:', missingEnvVars);
            throw new Error(`Missing required environment variables: ${missingEnvVars.join(', ')}`);
        }
    }

    /**
     * Register process event handlers for graceful shutdown
     */
    registerProcessHandlers() {
        // Handle unhandled promise rejections
        process.on('unhandledRejection', (err, promise) => {
            logger.error('Unhandled Rejection:', {message: err.message, stack: err.stack, promise, error: err});
            logger.info('Server shutting down due to unhandled rejection.');
            this.shutdown(1);
        });

        // Add event listener for uncaught exceptions
        process.on('uncaughtException', (err) => {
            logger.error('Uncaught Exception:', {message: err.message, stack: err.stack, error: err});
            logger.info('Server shutting down due to uncaught exception.');
            this.shutdown(1);
        });

        // Add SIGTERM handler for graceful shutdown with Docker/Kubernetes
        process.on('SIGTERM', () => {
            logger.info('SIGTERM received. Shutting down gracefully.');
            this.shutdown(0);
        });
    }

    /**
     * Initialize the serverwith all middleware and routes
     */
    async initialize() {
        if (this.isInitialized) {
            logger.warn('Server already initialized');
            return this;
        }

        // Setup middleware
        appMiddleware.setupMiddleware(this.app);

        // Setup basic health check route - unprotected and without API prefix
        // Health endpoints should NEVER use caching
        this.app.get('/health', noCacheResponse(), appController.getHealth);
        
        // Import auth middleware for CSRF protection
        const authMiddlewareModule = await import('./middleware/auth.middleware.js');
        const { csrfProtection, attachCsrfToken } = authMiddlewareModule;
        
        // Apply CSRF token attachment to all API routes (sets cookie if missing)
        this.app.use('/api', attachCsrfToken);
        
        // Apply CSRF validation to state-changing requests on protected routes
        // Note: Exempt routes are handled within the middleware itself
        this.app.use('/api', csrfProtection);
        
        // Import route modules (lazy load to avoid circular dependencies)
        const [
            authRoutesModule,
            userRoutesModule,
            appRoutesModule,
            fileRoutesModule,
            cacheRoutesModule
        ] = await Promise.all([
            import('./routes/auth.routes.js'),
            import('./routes/user.routes.js'),
            import('./routes/app.routes.js'),
            import('./routes/file.routes.js'),
            import('./routes/cache.routes.js')
        ]);

        const authRouter = authRoutesModule.default ?? authRoutesModule.router ?? authRoutesModule;
        const userRouter = userRoutesModule.default ?? userRoutesModule.router ?? userRoutesModule;
        const appRouter = appRoutesModule.default ?? appRoutesModule.router ?? appRoutesModule;
        const fileRouter = fileRoutesModule.default ?? fileRoutesModule.router ?? fileRoutesModule;
        const cacheRouter = cacheRoutesModule.default ?? cacheRoutesModule.router ?? cacheRoutesModule;

        const authValidRoutes = authRoutesModule.validRoutes ?? authRouter.validRoutes ?? [];
        const userValidRoutes = userRoutesModule.validRoutes ?? userRouter.validRoutes ?? [];
        const appValidRoutes = appRoutesModule.validRoutes ?? appRouter.validRoutes ?? [];
        const fileValidRoutes = fileRoutesModule.validRoutes ?? fileRouter.validRoutes ?? [];
        const cacheValidRoutes = cacheRoutesModule.validRoutes ?? cacheRouter.validRoutes ?? [];

        appMiddleware.registerRoutes([
            '/health',
            ...appValidRoutes,
            ...authValidRoutes,
            ...userValidRoutes,
            ...fileValidRoutes,
            ...cacheValidRoutes
        ]);

        // Apply route validation middleware specifically to /api routes
        this.app.use('/api', appMiddleware.validateRoute);

        // API Routes
        this.app.use('/api/v1/auth', authRouter);
        this.app.use('/api/v1/users', userRouter);
        this.app.use('/api/v1/files', fileRouter);
        this.app.use('/api/v1/cache', cacheRouter);
        this.app.use('/api/v1', appRouter);

        // Handle undefined routes
        appMiddleware.handleUndefinedRoutes(this.app);

        // Error handling middleware
        this.app.use(errorHandler);

        this.isInitialized = true;
        return this;
    }

    /**
     * Connect to MongoDB database
     * @returns {Promise<Object>} Mongoose connection object
     */
    async connectDatabase() {
        try {
            this.dbConnection = await connectDB();
            
            // Initialize Yjs service after database connection
            const yjsService = getYjsService();
            await yjsService.initialize();
            
            return this.dbConnection;
        } catch (error) {
            logger.error('Failed to connect to database:', error);
            throw error;
        }
    }

    /**
     * Checks if Redis client is connected
     * @returns {boolean} true if Redis is connected
     */
    isRedisConnected() {
        return redisClient && redisClient.isReady;
    }

    /**
     * Get Redis client instance
     * @returns {Object} Redis client
     */
    getRedisClient() {
        return redisClient;
    }

    /**
     * Get database connection instance
     * @returns {Object} Mongoose connection
     */
    getDbConnection() {
        return mongoose.connection;
    }

    /**
     * Initialize email service
     * @returns {Promise<void>}
     */  
    async initializeEmailService() {
        try {
            const {initializeEmailService} = appController;
            logger.info('📧 Initializing email service...');

            const transporter = await initializeEmailService?.();
            if (transporter) {
                logger.info('✅ Email service initialized successfully');
            } else {
                logger.warn('⚠️ Email service not configured or disabled');
            }
        } catch (error) {
            logger.error('❌ Failed to initialize email service:', error);
            // Don't throw here - email service failure shouldn't prevent server startup
        }
    }

    /**
     * Check if email service is ready
     * @returns {boolean} true if email service is ready
     */
    isEmailServiceReady() {
        try {
            const {isEmailReady} = appController;
            return isEmailReady?.();
        } catch (error) {
            return false;
        }
    }

    /**
     * Get email service instance
     * @returns {Object} Email transporter
     */
    getEmailService() {
        try {
            const {getEmailTransporter} = appController;
            return getEmailTransporter?.();
        } catch (error) {
            logger.error('Failed to get email service:', error);
            return null;
        }
    }

    /**
     * Register process handlers for graceful shutdown
     */
    /**
     * Start the server
     * @param {number} port - Port to listen on (overrides environment variable)
     * @returns {Promise<Object>} Express server instance
     */
    async start(port) {
        try {
            // Initialize the server if not already done
            if (!this.isInitialized) {
                await this.initialize();
            }

            // Connect to database
            await this.connectDatabase();

            // Initialize email service
            await this.initializeEmailService();

            // Start the server using the HTTP server (shared with Express)
            const serverPort = port || this.config.port;
            return new Promise((resolve) => {
                this.server = this.httpServer.listen(serverPort, async () => {
                    // Start cache cleanup service if caching is enabled and cleanup is enabled
                    if (this.config.cacheEnabled && process.env.CACHE_CLEANUP_ENABLED !== 'false') {
                        try {
                            // Use hours instead of minutes, with conservative default
                            const cleanupIntervalHours = parseInt(process.env.CACHE_CLEANUP_INTERVAL_HOURS);
                            cleanupService.start(cleanupIntervalHours);
                        } catch (err) {
                            logger.warn('⚠️ Failed to start cache cleanup service:', err.message);
                        }
                    } else if (process.env.CACHE_CLEANUP_ENABLED === 'false') {
                        logger.info('🧹 Cache cleanup service disabled via configuration');
                    }

                    // Yjs service initialized - collaborative editing ready

                    

                    // Setup integrated Yjs WebSocket server on the same HTTP server
                    try {
                        logger.info('🚀 Setting up integrated Yjs WebSocket server');
                        
                        const fileControllerModule = await import('./controllers/file.controller.js');
                        const authMiddleware = await import('./middleware/auth.middleware.js');
                        const fileModelModule = await import('./models/file.model.js');
                        const FileModel = fileModelModule.default ?? fileModelModule.File ?? fileModelModule;
                        const yjsService = fileControllerModule.yjsService ?? fileControllerModule.getYjsService?.();

                        // Create WebSocket server using the existing HTTP server - standard Yjs pattern
                        // Handle both /yjs/ and /notifications paths appropriately
                        const wss = new WebSocket.Server({
                            server: this.httpServer
                        });

                        const persistence = yjsService?.getPersistence?.();

                        if (persistence) {
                            // Single coordinator owns: per-doc epoch (for stale-batch invalidation),
                            // batched writes (one timer per doc covering both Yjs snapshot AND
                            // file `updatedAt` so they stay consistent), and writeState gating so
                            // a reconnecting bindState always sees the freshest MongoDB state.
                            // Replaces the previous ad-hoc writeStatePromises Map, the
                            // cancelFn registry, the dual 500ms/3000ms debouncers, and the
                            // manual compaction race that used to live inline here.
                            const coordinator = new PersistenceCoordinator({
                                persistence,
                                touchFileMetadata: async (docName) => {
                                    const filePath = filePathFromDocName(docName);
                                    await FileModel.updateOne(
                                        { filePath, type: { $in: ['text', 'binary'] } },
                                        { updatedAt: new Date() }
                                    );
                                },
                            });

                            // Hand the coordinator + persistence to YjsService so create/delete/
                            // overwrite flows go through replaceContent (epoch-based) rather than
                            // racing with the live update listener.
                            yjsService?.setCoordinator?.(coordinator);

                            setPersistence({
                                provider: persistence,
                                bindState: async (docName, ydoc) => {
                                    await coordinator.bindState(docName, ydoc);
                                    // Redis cross-server sync (optional, non-fatal)
                                    try {
                                        await yjsService?.bindRedisAdapter?.(docName, ydoc);
                                    } catch (redisError) {
                                        logger.warn('Redis adapter bind failed; continuing MongoDB-only', {
                                            docName, error: redisError.message
                                        });
                                    }
                                },
                                writeState: async (docName, ydoc) => {
                                    await coordinator.writeState(docName, ydoc);
                                    try {
                                        await yjsService?.unbindRedisAdapter?.(docName, ydoc);
                                    } catch (redisError) {
                                        logger.warn('Redis adapter unbind failed', {
                                            docName, error: redisError.message
                                        });
                                    }
                                },
                            });

                            // Track coordinator for shutdown flush.
                            this.persistenceCoordinator = coordinator;

                            const redisStats = yjsService?.getRedisStats?.() ?? {isEnabled: false, isConnected: false};
                            if (redisStats.isEnabled && redisStats.isConnected) {
                                logger.info('Yjs WebSocket persistence bound to MongoDB with Redis pub/sub scaling (multi-server mode)');
                            } else {
                                logger.info('Yjs WebSocket persistence bound to MongoDB provider (single-server mode)');
                            }
                        } else {
                            logger.warn('Yjs WebSocket server started without persistence binding; collaborative changes will not be persisted.');
                        }
                        
                        // ── WebSocket route table ───────────────────────────────────
                        // Single dispatch point: path prefix -> handler.  Keeps the
                        // connection callback short and makes adding new WS endpoints
                        // a one-line change.
                        const wsRoutes = [
                            {
                                prefix: '/notifications',
                                handle: (ws, req) => notificationService.handleConnection(ws, req),
                            },
                            {
                                prefix: '/yjs/',
                                handle: async (ws, req) => {
                                    if (!persistence) {
                                        logger.error('Yjs persistence not initialized');
                                        ws.close(1011, 'Persistence unavailable');
                                        return;
                                    }
                                    const user = await authMiddleware.authenticateWebSocket?.(ws, req);
                                    // Canonical docName from URL.  All layers (docs map,
                                    // MongoDB key, yjsService) use this same un-encoded form.
                                    const docName = docNameFromUrlPath(req.url);
                                    const filePath = filePathFromDocName(docName);
                                    const file = await FileModel.findOne({ filePath });
                                    if (!file) {
                                        logger.warn('Yjs auth: file not found', { filePath, userId: user?.id });
                                        ws.close(4404, 'File not found');
                                        return;
                                    }
                                    if (!file.hasReadAccess(user.id)) {
                                        logger.warn('Yjs auth: access denied', { filePath, userId: user.id });
                                        ws.close(4403, 'Access denied');
                                        return;
                                    }
                                    const liveDoc = docs.get(docName);
                                    const connsBefore = liveDoc ? liveDoc.conns.size : 0;
                                    // --- TEMP DIAGNOSTIC: wrap ws.send + raw message listener to trace per-conn frames
                                    const __connId = Math.random().toString(36).slice(2, 8);
                                    const __origSend = ws.send.bind(ws);
                                    ws.send = (data, ...rest) => {
                                        try {
                                            const len = data?.byteLength ?? data?.length ?? 0;
                                            let kind = 'other';
                                            if (data instanceof Uint8Array && data.length > 0) {
                                                // message type is first varuint byte (0=sync, 1=awareness)
                                                const t = data[0];
                                                if (t === 0 && data.length > 1) {
                                                    // sync subtype is next varuint byte
                                                    kind = `sync-step-${data[1]}`;
                                                } else if (t === 1) {
                                                    kind = 'awareness';
                                                } else {
                                                    kind = `type-${t}`;
                                                }
                                            }
                                            logger.info('[Yjs] WS SEND', { connId: __connId, docName, len, kind });
                                        } catch {}
                                        return __origSend(data, ...rest);
                                    };
                                    ws.on('message', (data) => {
                                        try {
                                            const buf = data instanceof Buffer ? data : Buffer.from(data);
                                            let kind = 'other';
                                            if (buf.length > 0) {
                                                const t = buf[0];
                                                if (t === 0 && buf.length > 1) kind = `sync-step-${buf[1]}`;
                                                else if (t === 1) kind = 'awareness';
                                                else kind = `type-${t}`;
                                            }
                                            logger.info('[Yjs] WS RECV', { connId: __connId, docName, len: buf.length, kind });
                                        } catch {}
                                    });
                                    setupWSConnection(ws, req, { docName, gc: false });
                                    const liveDocAfter = docs.get(docName);
                                    const connsAfter = liveDocAfter ? liveDocAfter.conns.size : 0;
                                    let docStateLen = 0;
                                    let docContentTextLen = 0;
                                    try {
                                        if (liveDocAfter) {
                                            docStateLen = (await import('yjs')).encodeStateAsUpdate(liveDocAfter).length;
                                            docContentTextLen = liveDocAfter.getText('content').toString().length;
                                        }
                                    } catch {}
                                    logger.info('[Yjs] WS CONNECT', { connId: __connId, userId: user.id, docName, connsBefore, connsAfter, docStateLen, docContentTextLen });
                                    ws.on('close', (code, reason) => {
                                        const ld = docs.get(docName);
                                        const remaining = ld ? ld.conns.size : 0;
                                        logger.info('[Yjs] WS CLOSE', {
                                            connId: __connId,
                                            userId: user.id,
                                            docName,
                                            code,
                                            reason: reason?.toString?.() || '',
                                            remaining,
                                        });
                                    });
                                },
                            },
                        ];

                        wss.on('connection', async (ws, req) => {
                            try {
                                const urlPath = (req.url || '').split('?')[0];
                                const route = wsRoutes.find(r => urlPath === r.prefix || urlPath.startsWith(r.prefix));
                                if (!route) {
                                    logger.warn('Invalid WebSocket path, rejecting connection', { urlPath });
                                    ws.close(1008, 'Invalid path');
                                    return;
                                }
                                await route.handle(ws, req);
                            } catch (error) {
                                // Auth failures are common (expired tokens from stale tabs).
                                // Log at debug to avoid flooding production logs, and close
                                // with 4401 so well-behaved clients can stop retrying.
                                const isAuthError = /token|auth/i.test(error?.message || '');
                                if (isAuthError) {
                                    logger.debug('WebSocket auth rejected', { url: req.url, message: error.message });
                                    try { ws.close(4401, 'Authentication failed'); } catch { /* already closed */ }
                                } else {
                                    logger.error('WebSocket connection error:', error);
                                    try { ws.close(1008, 'Connection error'); } catch { /* already closed */ }
                                }
                            }
                        });
                        
                        // Handle server errors
                        wss.on('error', (error) => {
                            logger.error('Integrated WebSocket server error:', error);
                        });
                        
                        // Store WebSocket server reference for shutdown
                        this.yjsWebSocketServer = wss;

                        // Give YjsService a reference to the WS server's in-memory
                        // docs Map so replaceContent can operate on live wsDocs.
                        yjsService?.setWsDocsMap?.(docs);
                        
                        logger.info('✅ Integrated Yjs WebSocket server running on /yjs path');
                        
                    } catch (error) {
                        logger.error('❌ Failed to start integrated Yjs WebSocket server:', error);
                    }

                    // Initialize notification WebSocket service (routing handled in main WebSocket server above)
                    try {
                        logger.info('🔔 Setting up notification WebSocket server');
                        // Initialize the service without creating a separate WebSocket server
                        notificationService.initialize();
                        logger.info('✅ Notification WebSocket server running on /notifications path');
                    } catch (error) {
                        logger.error('❌ Failed to start notification WebSocket server:', error);
                    }

                    // Log initial health check before showing startup banner
                    // Use the getHealth function from appController, but mock req/res
                    const mockReq = {ip: 'startup'};
                    const mockRes = {
                        json: () => {
                        }
                    }; // Suppress duplicate log output

                    appController.getHealth(mockReq, mockRes);

                    // Now show startup banner
                    await logger.startupMessage("Filesystem One", serverPort, this.config.environment);

                    resolve(this.server);
                });
            });
        } catch (error) {
            logger.error('Failed to start server:', error);
            throw error;
        }
    }
    


    /**
     * Stop the server and close connections
     * @returns {Promise<void>}
     */
    async stop() {
        return new Promise((resolve, reject) => {
            if (!this.server) {
                logger.warn('Server not running, nothing to stop');
                return resolve();
            }

            logger.info('Stopping server...');

            this.server.close(async (err) => {
                if (err) {
                    logger.error('Error stopping server:', err);
                    return reject(err);
                }

                try {
                    // Stop cache cleanup service
                    if (cleanupService) {
                        cleanupService.stop();
                        logger.info('Cache cleanup service stopped');
                    }

                    // Cleanup Yjs service
                    try {
                        const fileControllerModule = await import('./controllers/file.controller.js');
                        await fileControllerModule.yjsService?.destroy?.();
                        logger.info('Yjs service cleaned up');
                    } catch (error) {
                        logger.warn('Failed to cleanup Yjs service:', error.message);
                    }

                    // Close database connection
                    if (mongoose.connection.readyState !== 0) {
                        logger.info('Closing database connection...');
                        await mongoose.connection.close();
                        logger.info('Database connection closed');
                    }

                    // Close Redis connection if active
                    if (this.isRedisConnected()) {
                        logger.info('Closing Redis connection...');
                        await redisClient.quit();
                        logger.info('Redis connection closed');
                    }
                    
                    // Close integrated Yjs WebSocket server if active
                    if (this.yjsWebSocketServer) {
                        logger.info('Closing integrated Yjs WebSocket server...');
                        try {
                            this.yjsWebSocketServer.close();
                            logger.info('Integrated Yjs WebSocket server closed');
                        } catch (err) {
                            logger.warn('Error closing integrated Yjs WebSocket server:', err.message);
                        }
                        this.yjsWebSocketServer = null;
                    }

                    // Flush pending Yjs writes before exit
                    if (this.persistenceCoordinator) {
                        try {
                            await this.persistenceCoordinator.shutdown();
                            logger.info('Yjs persistence coordinator flushed');
                        } catch (err) {
                            logger.warn('Error flushing persistence coordinator:', err.message);
                        }
                        this.persistenceCoordinator = null;
                    }

                    // Shutdown notification WebSocket service
                    try {
                        notificationService.shutdown();
                        logger.info('Notification WebSocket service shut down');
                    } catch (error) {
                        logger.warn('Error shutting down notification WebSocket service:', error.message);
                    }

                    logger.info('Server stopped successfully');
                    this.server = null;
                    resolve();
                } catch (error) {
                    logger.error('Error during cleanup:', error);
                    reject(error);
                }
            });
        });
    }

    /**
     * Shutdown the server and optionally exit the process
     * @param {number} exitCode - Process exit code
     */
    async shutdown(exitCode = 0) {
        try {
            await this.stop();
            process.exit(exitCode);
        } catch (error) {
            logger.error('Error during shutdown:', error);
            process.exit(1);
        }
    }

    /**
     * Get the Express app instance
     * @returns {Object} Express app
     */
    getApp() {
        return this.app;
    }

    /**
     * Get the server instance
     * @returns {Object} HTTP server
     */
    getServer() {
        return this.server;
    }

    /**
     * Get server configuration
     * @returns {Object} Server configuration
     */
    getConfig() {
        return {...this.config};
    }
}

// Create singleton instance
const serverInstance = new Server();

export const start = (port) => serverInstance.start(port);
export const stop = () => serverInstance.stop();
export const getApp = () => serverInstance.getApp();
export const getServer = () => serverInstance.getServer();
export const getConfig = () => serverInstance.getConfig();
export const isRedisConnected = () => serverInstance.isRedisConnected();
export const getRedisClient = () => serverInstance.getRedisClient();
export const getDbConnection = () => serverInstance.getDbConnection();
export const isEmailReady = () => appMiddleware.isEmailReady?.();
export const getEmailTransporter = () => appMiddleware.getEmailTransporter?.();

export {Server, serverInstance};
export default serverInstance;
