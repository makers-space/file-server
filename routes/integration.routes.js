import {Router} from 'express';
import integrationController from '../controllers/integration.controller.js';
import * as authMiddleware from '../middleware/auth.middleware.js';
import {validateRequest} from '../middleware/validation.middleware.js';
import {integrationSchemas, integrationParamSchemas} from '../models/schemas.js';

const router = Router();

// Routes registered for route validation middleware
router.validRoutes = [
    '/api/v1/integrations',                              // List / create integrations
    '/api/v1/integrations/:integrationId',               // Get / update / delete
    '/api/v1/integrations/:integrationId/verify',        // Verification handshake
    '/api/v1/integrations/:integrationId/rotate-secret', // Signing secret rotation
    '/api/v1/integrations/:integrationId/send',          // Send file to external API
    '/api/v1/integrations/:integrationId/deliveries'     // Delivery log
];

// All integration routes require authentication
router.use(authMiddleware.verifyToken());

/**
 * @route   POST /api/v1/integrations
 * @desc    Register an external API integration
 * @access  Private (global scope: admin; user scope: CREATE_CONTENT — premium hook)
 */
router.post('/',
    validateRequest(integrationSchemas.createIntegration),
    integrationController.createIntegration
);

/**
 * @route   GET /api/v1/integrations
 * @desc    List integrations visible to requester
 * @access  Private
 */
router.get('/', integrationController.listIntegrations);

/**
 * @route   GET /api/v1/integrations/:integrationId
 * @desc    Get integration details (secrets never included)
 * @access  Private (admin, owner, or global)
 */
router.get('/:integrationId',
    validateRequest(integrationParamSchemas.integrationId, 'params'),
    integrationController.getIntegration
);

/**
 * @route   PATCH /api/v1/integrations/:integrationId
 * @desc    Update integration; URL changes reset verification status
 * @access  Private (owner or admin)
 */
router.patch('/:integrationId',
    validateRequest(integrationParamSchemas.integrationId, 'params'),
    validateRequest(integrationSchemas.updateIntegration),
    integrationController.updateIntegration
);

/**
 * @route   DELETE /api/v1/integrations/:integrationId
 * @desc    Delete an integration
 * @access  Private (owner or admin)
 */
router.delete('/:integrationId',
    validateRequest(integrationParamSchemas.integrationId, 'params'),
    integrationController.deleteIntegration
);

/**
 * @route   POST /api/v1/integrations/:integrationId/verify
 * @desc    Challenge/response verification of the external endpoint
 * @access  Private (owner or admin)
 */
router.post('/:integrationId/verify',
    validateRequest(integrationParamSchemas.integrationId, 'params'),
    integrationController.verifyIntegration
);

/**
 * @route   POST /api/v1/integrations/:integrationId/rotate-secret
 * @desc    Rotate the HMAC signing secret
 * @access  Private (owner or admin)
 */
router.post('/:integrationId/rotate-secret',
    validateRequest(integrationParamSchemas.integrationId, 'params'),
    integrationController.rotateSecret
);

/**
 * @route   POST /api/v1/integrations/:integrationId/send
 * @desc    Send file metadata (and optionally content) to a verified endpoint
 * @access  Private (requires read access on the file)
 */
router.post('/:integrationId/send',
    validateRequest(integrationParamSchemas.integrationId, 'params'),
    validateRequest(integrationSchemas.sendFile),
    integrationController.sendFile
);

/**
 * @route   GET /api/v1/integrations/:integrationId/deliveries
 * @desc    Recent delivery log + stats
 * @access  Private (owner or admin)
 */
router.get('/:integrationId/deliveries',
    validateRequest(integrationParamSchemas.integrationId, 'params'),
    integrationController.getDeliveries
);

export default router;
