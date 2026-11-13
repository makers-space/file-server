import mongoose from 'mongoose';

export const NOTIFICATION_SERVICE = 'fs-one';
const KEEP_DAYS = 30;

const notificationSchema = new mongoose.Schema({
    service: { type: String, default: NOTIFICATION_SERVICE, immutable: true, index: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, required: true },
    level: { type: String, enum: ['success', 'info', 'warning', 'error'], default: 'info' },
    title: { type: String, default: '' },
    message: { type: String, required: true },
    path: { type: String, default: null },
    read: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now, expires: KEEP_DAYS * 24 * 60 * 60 }
});
notificationSchema.index({ service: 1, user: 1, createdAt: -1 });

const Notification = mongoose.models.Notification || mongoose.model('Notification', notificationSchema);

export default Notification;
