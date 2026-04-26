import mongoose from 'mongoose';

/**
 * Group roles (separate from system-level roles in rights.js):
 *   OWNER – full control: manage members, assign permissions, delete group, read/write all group files
 *   WRITE – can create/edit/delete files and subdirectories inside the group folder
 *   READ  – read-only access to all files inside the group folder
 *
 * Permissions propagate to every file and directory nested under the group's
 * rootFolderPath — individual file permissions are not used inside group folders.
 */
export const GROUP_ROLES = {
    OWNER: 'OWNER',
    WRITE: 'WRITE',
    READ: 'READ'
};

export const GROUP_ROLE_HIERARCHY = {
    [GROUP_ROLES.OWNER]: 3,
    [GROUP_ROLES.WRITE]: 2,
    [GROUP_ROLES.READ]: 1
};

const memberSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    role: {
        type: String,
        enum: Object.values(GROUP_ROLES),
        default: GROUP_ROLES.READ
    },
    joinedAt: {
        type: Date,
        default: Date.now
    }
}, {_id: false});

const groupSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Group name is required'],
        trim: true,
        minlength: [2, 'Group name must be at least 2 characters'],
        maxlength: [100, 'Group name must be less than 100 characters']
    },
    description: {
        type: String,
        trim: true,
        maxlength: 500
    },
    avatar: {
        type: String,
        default: null
    },
    // Privacy: public groups are discoverable, private require invite
    privacy: {
        type: String,
        enum: ['public', 'private'],
        default: 'private'
    },
    members: [memberSchema],
    // Cached member count for efficient queries
    memberCount: {
        type: Number,
        default: 0
    },
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    // Filesystem path for this group's root folder (e.g. /groups/<id>)
    rootFolderPath: {
        type: String,
        default: null
    }
}, {
    timestamps: true
});

// Indexes
groupSchema.index({createdBy: 1});
groupSchema.index({'members.user': 1});
groupSchema.index({privacy: 1, name: 1});
groupSchema.index({rootFolderPath: 1}); // used by findGroupForFilePath ancestor lookup

// Keep cached counts in sync
groupSchema.pre('save', function (next) {
    this.memberCount = this.members.length;
    next();
});

/**
 * Get a member's role in this group
 */
groupSchema.methods.getMemberRole = function (userId) {
    const member = this.members.find(m => m.user.equals(userId));
    return member ? member.role : null;
};

/**
 * Check if a user is a member of this group
 */
groupSchema.methods.isMember = function (userId) {
    return this.members.some(m => m.user.equals(userId));
};

/**
 * Check if a user meets a minimum role requirement
 */
groupSchema.methods.hasMinRole = function (userId, minRole) {
    const memberRole = this.getMemberRole(userId);
    if (!memberRole) return false;
    return GROUP_ROLE_HIERARCHY[memberRole] >= GROUP_ROLE_HIERARCHY[minRole];
};

const Group = mongoose.models.Group || mongoose.model('Group', groupSchema);

export default Group;
