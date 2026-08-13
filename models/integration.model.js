import mongoose from 'mongoose';
import crypto from 'node:crypto';

/**
 * External Integration model
 *
 * Represents a verified external API endpoint that FilesystemOne is allowed
 * to send file content and metadata to.
 *
 * Scopes:
 *   global – registered by admins (MANAGE_ALL_CONTENT); usable by every user
 *   user   – personal export destination registered by an individual user
 *            (requires CREATE_CONTENT right — the "premium" hook); usable
 *            only by its owner
 *
 * Statuses:
 *   pending  – registered but the endpoint has not yet completed the
 *              challenge/response verification handshake
 *   verified – endpoint answered the signed verification challenge; files
 *              may be delivered
 *   disabled – manually disabled by owner/admin; no deliveries allowed
 */

export const INTEGRATION_SCOPES = {
    GLOBAL: 'global',
    USER: 'user'
};

export const INTEGRATION_STATUSES = {
    PENDING: 'pending',
    VERIFIED: 'verified',
    DISABLED: 'disabled'
};

const DELIVERY_LOG_LIMIT = 20;

const deliveryLogSchema = new mongoose.Schema({
    filePath: {type: String, required: true},
    event: {type: String, default: 'file.export'},
    success: {type: Boolean, required: true},
    httpStatus: {type: Number, default: null},
    error: {type: String, default: null},
    includedContent: {type: Boolean, default: false},
    sentBy: {type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true},
    sentAt: {type: Date, default: Date.now},
    durationMs: {type: Number, default: null}
}, {_id: false});

const integrationSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Integration name is required'],
        trim: true,
        minlength: [2, 'Integration name must be at least 2 characters'],
        maxlength: [100, 'Integration name must be less than 100 characters']
    },
    description: {
        type: String,
        trim: true,
        maxlength: 500,
        default: ''
    },
    // Base URL of the external API endpoint that receives payloads
    baseUrl: {
        type: String,
        required: [true, 'Integration base URL is required'],
        trim: true,
        maxlength: 2048
    },
    // Optional API key sent to the remote endpoint on every request
    apiKey: {
        type: String,
        default: null,
        select: false,
        maxlength: 500
    },
    // Header used to transmit the API key
    apiKeyHeader: {
        type: String,
        default: 'X-Api-Key',
        maxlength: 100
    },
    // Secret used to HMAC-sign outgoing payloads so receivers can verify origin
    signingSecret: {
        type: String,
        select: false
    },
    scope: {
        type: String,
        enum: Object.values(INTEGRATION_SCOPES),
        default: INTEGRATION_SCOPES.USER,
        index: true
    },
    owner: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        index: true
    },
    status: {
        type: String,
        enum: Object.values(INTEGRATION_STATUSES),
        default: INTEGRATION_STATUSES.PENDING,
        index: true
    },
    verifiedAt: {
        type: Date,
        default: null
    },
    lastVerificationError: {
        type: String,
        default: null
    },
    // Rolling log of the most recent deliveries (capped)
    deliveryLog: {
        type: [deliveryLogSchema],
        default: []
    },
    stats: {
        totalDeliveries: {type: Number, default: 0},
        failedDeliveries: {type: Number, default: 0},
        lastDeliveryAt: {type: Date, default: null}
    }
}, {
    timestamps: true,
    toJSON: {
        transform(doc, ret) {
            // Consistent public shape: expose id, never leak secrets
            ret.id = ret._id.toString();
            delete ret._id;
            delete ret.apiKey;
            delete ret.signingSecret;
            delete ret.__v;
            return ret;
        }
    }
});

integrationSchema.index({scope: 1, status: 1});
integrationSchema.index({owner: 1, name: 1});

/**
 * Generate a fresh signing secret (returned in plain form exactly once by the API)
 */
integrationSchema.statics.generateSigningSecret = function () {
    return crypto.randomBytes(32).toString('hex');
};

/**
 * Record a delivery attempt in the capped delivery log and update stats
 */
integrationSchema.methods.recordDelivery = function (entry) {
    this.deliveryLog.unshift({
        filePath: entry.filePath,
        event: entry.event || 'file.export',
        success: !!entry.success,
        httpStatus: entry.httpStatus ?? null,
        error: entry.error ?? null,
        includedContent: !!entry.includedContent,
        sentBy: entry.sentBy,
        sentAt: entry.sentAt || new Date(),
        durationMs: entry.durationMs ?? null
    });
    if (this.deliveryLog.length > DELIVERY_LOG_LIMIT) {
        this.deliveryLog = this.deliveryLog.slice(0, DELIVERY_LOG_LIMIT);
    }
    this.stats.totalDeliveries += 1;
    if (!entry.success) {
        this.stats.failedDeliveries += 1;
    }
    this.stats.lastDeliveryAt = new Date();
};

/**
 * Whether the given user may USE this integration (send files through it)
 */
integrationSchema.methods.canBeUsedBy = function (userId) {
    if (this.status !== INTEGRATION_STATUSES.VERIFIED) return false;
    if (this.scope === INTEGRATION_SCOPES.GLOBAL) return true;
    return this.owner.toString() === userId.toString();
};

/**
 * Whether the given user may MANAGE this integration (edit/verify/delete)
 * Admin override is handled at the controller level via rights.
 */
integrationSchema.methods.isOwnedBy = function (userId) {
    return this.owner.toString() === userId.toString();
};

// Guard against model recompilation (vitest re-evaluates modules per test file)
const Integration = mongoose.model('Integration', integrationSchema);

export default Integration;
