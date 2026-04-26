import User from '../models/user.model.js';
import {Connection} from '../models/user.model.js';
import File from '../models/file.model.js';
import Group, {GROUP_ROLES, GROUP_ROLE_HIERARCHY} from '../models/group.model.js';
import Log from '../models/log.model.js';
import mongoose from 'mongoose';
import {asyncHandler} from '../middleware/app.middleware.js';
import {AppError} from '../middleware/error.middleware.js';
import bcrypt from 'bcryptjs';
import {hasRight, RIGHTS, ROLES} from '../config/rights.js';
import {
    normalizeRoles,
    processRolesWithApproval
} from '../middleware/user.middleware.js';
import {cache} from '../middleware/cache.middleware.js';
import logger from '../utils/app.logger.js';
import {sanitizeObject, sanitizeHtmlInObject, sanitizeHtmlInput} from '../utils/sanitize.js';
import {
    parseFilters,
    getFilterSummary,
    applyFiltersToAggregation
} from './app.controller.js';
import {sendPasswordChangedEmail} from './auth.controller.js';

// Helper function to format user response
const formatUserResponse = (user) => {
    // Create a clean user object without sensitive data
    const roles = normalizeRoles(user.roles);

    // Handle active field - if it doesn't exist, default to true
    const active = user.active !== undefined ? user.active : true;

    return {
        id: user._id || user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        username: user.username,
        email: user.email,
        roles: roles,
        emailVerified: user.emailVerified,
        profilePhoto: user.profilePhoto,
        twoFactorEnabled: user.twoFactorEnabled,
        active: active,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt
    };
};
// Helper function to format public user response (limited info)
const formatPublicUserResponse = (user) => {
    const roles = normalizeRoles(user.roles);
    
    return {
        id: user._id || user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        username: user.username,
        email: user.email,
        roles: roles
    };
};

const userController = {
    // Get public users (authenticated users only - limited info)
    getPublicUsers: asyncHandler(async (req, res, next) => {
        try {
            // Parse filters and options using the universal filter system
            const {filters, options} = parseFilters(req.query);

            // Override generic search with user-specific field search
            if (req.query.search) {
                const escapedSearch = req.query.search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                const searchRegex = { $regex: escapedSearch, $options: 'i' };
                filters.$or = [
                    { username: searchRegex },
                    { firstName: searchRegex },
                    { lastName: searchRegex },
                    { email: searchRegex }
                ];
            }

            // Only show active users by default
            if (!filters.active) {
                filters.active = true;
            }

            // Create the base query - only select public fields
            let query = User.find(filters).select('firstName lastName username email roles');

            // Apply sorting (default to firstName)
            if (Object.keys(options.sort).length > 0) {
                query = query.sort(options.sort);
            } else {
                query = query.sort({ firstName: 1, lastName: 1 });
            }

            // Apply pagination
            if (options.pagination.skip !== undefined) {
                query = query.skip(options.pagination.skip);
            }
            if (options.pagination.limit !== undefined) {
                query = query.limit(options.pagination.limit);
            }

            // Execute the query
            const users = await query.exec();

            // Get total count for pagination metadata
            const totalUsers = await User.countDocuments(filters);

            // Get filter summary for response metadata
            const filterSummary = getFilterSummary(filters, options);

            logger.info(`${logger.safeColor(logger.colors.cyan)}[User Controller]${logger.safeColor(logger.colors.reset)} Public users fetched`, {
                count: users.length,
                totalUsers,
                requestedBy: req.user?.username
            });

            res.status(200).json({
                success: true,
                message: 'Public users retrieved successfully',
                users: users.map(formatPublicUserResponse),
                meta: {
                    count: users.length,
                    totalUsers,
                    pagination: {
                        page: filterSummary.pagination?.page || 1,
                        limit: filterSummary.pagination?.limit || users.length,
                        totalPages: filterSummary.pagination ? Math.ceil(totalUsers / filterSummary.pagination.limit) : 1
                    },
                    timestamp: new Date().toISOString()
                }
            });
        } catch (error) {
            logger.error(`${logger.safeColor(logger.colors.red)}[User Controller]${logger.safeColor(logger.colors.reset)} Error fetching public users:`, {
                error: error.message,
                requestedBy: req.user?.username
            });
            return next(new AppError(`Failed to retrieve public users: ${error.message}`, 500));
        }
    }),

    // Get all users (admin only)
    getAllUsers: asyncHandler(async (req, res, next) => {
        try {
            // Parse filters and options using the universal filter system
            const {filters, options} = parseFilters(req.query);

            // Create the base query with the +active field
            let query = User.find(filters).select('+active');

            // Apply sorting
            if (Object.keys(options.sort).length > 0) {
                query = query.sort(options.sort);
            }

            // Apply pagination
            if (options.pagination.skip !== undefined) {
                query = query.skip(options.pagination.skip);
            }
            if (options.pagination.limit !== undefined) {
                query = query.limit(options.pagination.limit);
            }

            // Execute the query
            const users = await query.exec();

            // Get total count for pagination metadata
            const totalUsers = await User.countDocuments(filters);

            // Debug log to check if active field is being returned
            if (users.length > 0) {
                logger.info(`${logger.safeColor(logger.colors.yellow)}[User Controller Debug]${logger.safeColor(logger.colors.reset)} Sample user active field:`, {
                    userId: users[0]._id,
                    active: users[0].active,
                    hasActiveField: users[0].hasOwnProperty('active'),
                    allFields: Object.keys(users[0].toObject()),
                    roles: users[0].roles
                });
            }

            // Get filter summary for response metadata
            const filterSummary = getFilterSummary(filters, options);

            logger.info(`${logger.safeColor(logger.colors.cyan)}[User Controller]${logger.safeColor(logger.colors.reset)} Users fetched from DB`, {
                count: users.length,
                totalUsers,
                filters: filterSummary
            });

            res.status(200).json({
                success: true,
                message: 'Users retrieved successfully',
                users: users.map(formatUserResponse),
                meta: {
                    count: users.length,
                    totalUsers,
                    pagination: {
                        page: filterSummary.pagination?.page || 1,
                        limit: filterSummary.pagination?.limit || users.length,
                        totalPages: filterSummary.pagination ? Math.ceil(totalUsers / filterSummary.pagination.limit) : 1
                    },
                    filters: filterSummary,
                    timestamp: new Date().toISOString()
                }
            });
        } catch (error) {
            logger.error(`${logger.safeColor(logger.colors.red)}[User Controller]${logger.safeColor(logger.colors.reset)} Error fetching all users:`, error);
            next(error);
        }
    }),

    // Get single user by ID
    getUserById: asyncHandler(async (req, res, next) => {
        const userId = req.params.id;

        try {
            logger.info(`${logger.safeColor(logger.colors.cyan)}[User Controller]${logger.safeColor(logger.colors.reset)} Fetching user by ID`, {userId});

            // No need for direct cache interaction - handled by middleware
            const user = await User.findById(userId);

            if (!user) {
                logger.warn(`${logger.safeColor(logger.colors.yellow)}[User Controller]${logger.safeColor(logger.colors.reset)} User not found`, {userId});
                return next(new AppError('No user found with that ID', 404));
            }
            logger.info(`${logger.safeColor(logger.colors.green)}[User Controller]${logger.safeColor(logger.colors.reset)} User found successfully`, {userId});
            res.status(200).json({
                success: true,
                message: 'User retrieved successfully',
                user: formatUserResponse(user),
                meta: {
                    timestamp: new Date().toISOString()
                }
            });
        } catch (error) {
            logger.error(`${logger.safeColor(logger.colors.red)}[User Controller]${logger.safeColor(logger.colors.reset)} Error fetching user ${userId}:`, error);
            next(error);
        }
    }),

    // Create a new user
    createUser: asyncHandler(async (req, res, next) => {
        try {
            logger.info(`${logger.safeColor(logger.colors.cyan)}[User Controller]${logger.safeColor(logger.colors.reset)} Creating new user`, {
                requestorId: req.user ? req.user.id : 'Unknown user',
                ip: req.ip
            });

            // Extract password separately as it should not be HTML sanitized
            const {password, roles} = req.body;

            // Sanitize HTML content in input fields to prevent XSS
            const htmlSanitizedData = sanitizeHtmlInObject(req.body);

            // Log sanitized version for security (without actual sensitive data)
            const logSanitizedData = sanitizeObject(req.body);

            // Process roles with approval workflow if needed
            let finalRoles = roles || [ROLES.USER];
            let roleApprovalData = null;

            if (req.roleApprovalRequired) {
                // Use role approval workflow for unauthorized roles
                const approvalResult = processRolesWithApproval(roles, req.user);
                finalRoles = approvalResult.assignedRoles;
                roleApprovalData = {
                    pendingRoles: approvalResult.pendingRoles,
                    roleApprovalStatus: approvalResult.roleApprovalStatus,
                    roleApprovalRequest: approvalResult.roleApprovalRequest
                };
                
                logger.info(`${logger.safeColor(logger.colors.cyan)}[User Controller]${logger.safeColor(logger.colors.reset)} Role approval workflow applied`, {
                    assignedRoles: finalRoles,
                    pendingRoles: approvalResult.pendingRoles,
                    status: approvalResult.roleApprovalStatus
                });
            }

            const newUser = new User({
                firstName: htmlSanitizedData.firstName,
                lastName: htmlSanitizedData.lastName,
                username: htmlSanitizedData.username,
                email: htmlSanitizedData.email,
                password: password, // Use original password for hashing
                roles: finalRoles, // Use processed roles
                // Add role approval data if applicable
                ...(roleApprovalData && roleApprovalData.pendingRoles && roleApprovalData.pendingRoles.length > 0 && {
                    roleApprovalRequest: roleApprovalData.roleApprovalRequest
                })
            });

            const savedUser = await newUser.save();

            // Use sophisticated cache invalidation for new user creation
            await cache.invalidateAllRelatedCaches('user', savedUser._id, savedUser._id);

            logger.info(`${logger.safeColor(logger.colors.green)}[User Controller]${logger.safeColor(logger.colors.reset)} User created successfully`, {
                userId: savedUser._id,
                username: savedUser.username
            });

            // Prepare response with role approval information
            const response = {
                success: true,
                message: roleApprovalData && roleApprovalData.roleApprovalStatus === 'APPROVED' 
                    ? 'Account created with approved roles by owner.'
                    : roleApprovalData && roleApprovalData.pendingRoles && roleApprovalData.pendingRoles.length > 0
                    ? 'User created successfully. Some roles are pending approval.'
                    : 'User created successfully',
                user: formatUserResponse(savedUser),
                meta: {
                    timestamp: new Date().toISOString()
                }
            };

            // Add role approval metadata if applicable
            if (roleApprovalData) {
                response.meta = {
                    ...response.meta,
                    ...(roleApprovalData.pendingRoles && roleApprovalData.pendingRoles.length > 0 && {
                        pendingRoles: roleApprovalData.pendingRoles
                    }),
                    ...(roleApprovalData.roleApprovalStatus && {
                        roleApprovalStatus: roleApprovalData.roleApprovalStatus
                    })
                };
            }

            res.status(201).json(response);
        } catch (error) {
            logger.error(`${logger.safeColor(logger.colors.red)}[User Controller]${logger.safeColor(logger.colors.reset)} Error creating user:`, {
                message: error.message,
                userId: req.body?.email || 'unknown'
            });
            if (error.code === 11000) {
                const field = Object.keys(error.keyPattern)[0];
                logger.warn(`Duplicate key error for field: ${field}`, {field});
                return res.status(409).json({
                    success: false,
                    message: `${field} already exists. Please use a different ${field}.`,
                    meta: {
                        timestamp: new Date().toISOString()
                    }
                });
            }
            return res.status(400).json({
                success: false,
                message: `Error creating user: ${error.message}`,
                meta: {
                    timestamp: new Date().toISOString()
                }
            });
        }
    }),

    // Update User (supports role request auto-approval)
    updateUser: asyncHandler(async (req, res, next) => {
        const userId = req.params.id;
        logger.info(`${logger.safeColor(logger.colors.cyan)}[User Controller]${logger.safeColor(logger.colors.reset)} Updating user ${userId}`, {
            requestorId: req.user ? req.user.id : 'Unknown user',
            ip: req.ip
        });

        try {
            if (req.body.password) {
                logger.warn(`Attempt to update password via updateUser route for user ${userId}. Password field removed.`);
                delete req.body.password;
            }

            if (!hasRight(req.user.roles, RIGHTS.MANAGE_ALL_USERS) && req.user.id !== req.params.id) {
                logger.warn('Access denied: User attempting to update another user\'s profile without MANAGE_ALL_USERS right', {
                    requestorId: req.user.id,
                    targetUserId: req.params.id
                });
                return res.status(403).json({
                    success: false,
                    message: 'Access denied: You can only update your own profile',
                    timestamp: new Date().toISOString()
                });
            }

            if (!req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
                logger.warn('Invalid user ID format for update', {userId: req.params.id});
                return res.status(400).json({
                    success: false,
                    message: 'Invalid user ID format',
                    timestamp: new Date().toISOString()
                });
            }

            let user;
            try {
                user = await User.findById(req.params.id);
            } catch (findError) {
                logger.error(`Error finding user ${req.params.id} for update:`, {
                    message: findError.message,
                    stack: findError.stack,
                    error: findError
                });
                return res.status(500).json({
                    success: false,
                    message: `Database error during user lookup: ${findError.message}`,
                    timestamp: new Date().toISOString()
                });
            }

            if (!user) {
                logger.warn(`User not found for update: ${req.params.id}`);
                return res.status(404).json({
                    success: false,
                    message: 'User not found',
                    timestamp: new Date().toISOString()
                });
            }

            const allowedFields = ['firstName', 'lastName', 'email', 'username', 'profilePhoto'];
            if (hasRight(req.user.roles, RIGHTS.MANAGE_ALL_USERS)) {
                allowedFields.push('roles', 'active');
            }

            logger.debug('User update request', {
                userId: req.user.id,
                targetUserId: req.params.id,
                allowedFields,
                requestedFields: Object.keys(req.body)
            });

            const updates = {};
            Object.keys(req.body).forEach(key => {
                if (allowedFields.includes(key)) {
                    updates[key] = req.body[key];
                    logger.debug(`Including field ${key} in user update`, {
                        userId: req.user.id,
                        targetUserId: req.params.id,
                        field: key
                    });
                } else {
                    logger.debug(`Excluding field ${key} from user update (not in allowedFields)`, {
                        userId: req.user.id,
                        targetUserId: req.params.id,
                        field: key,
                        allowedFields
                    });
                }
            });

            // Check if roles are being updated and handle role requests
            if (updates.roles && hasRight(req.user.roles, RIGHTS.MANAGE_ALL_USERS)) {
                const newRoles = normalizeRoles(updates.roles);
                const currentPendingRoles = normalizeRoles(user.pendingRoles);
                
                // Check if the new roles include all pending roles
                if (user.roleApprovalStatus === 'PENDING' && currentPendingRoles.length > 0) {
                    const allPendingRolesIncluded = currentPendingRoles.every(pendingRole => 
                        newRoles.includes(pendingRole)
                    );
                    
                    if (allPendingRolesIncluded) {
                        // Auto-approve the role request since admin is granting the requested roles
                        logger.info(`Auto-approving role request for user ${userId} during admin update`, {
                            requestorId: req.user.id,
                            previousRoles: user.roles,
                            newRoles: newRoles,
                            pendingRoles: currentPendingRoles
                        });
                        
                        // Clear pending status and update approval metadata
                        updates.pendingRoles = [];
                        updates.roleApprovalStatus = 'APPROVED';
                        updates.roleApprovalRequest = {
                            ...user.roleApprovalRequest,
                            approvedBy: req.user.id,
                            approvedAt: new Date(),
                            reason: 'Role request approved via admin user update'
                        };
                    }
                }
            }

            if (Object.keys(updates).length === 0) {
                if (req.body.roles && !hasRight(req.user.roles, RIGHTS.MANAGE_ALL_USERS)) {
                    logger.info(`User ${req.user.id} attempted to update roles for user ${req.params.id} without permission. Ignoring roles update.`);
                    return res.json(formatUserResponse(user));
                }
                logger.warn('No valid fields to update', {userId: req.params.id});
                return res.status(400).json({
                    success: false,
                    message: 'Invalid request',
                    timestamp: new Date().toISOString()
                });
            }
            
            // Sanitize HTML content in update data before saving to database
            const sanitizedUpdates = sanitizeHtmlInObject(updates);

            let updatedUser;
            try {
                updatedUser = await User.findByIdAndUpdate(
                    req.params.id,
                    {$set: sanitizedUpdates},
                    {new: true, runValidators: true}
                ).select('+active'); // Include the active field in the response
            } catch (updateError) {
                logger.error(`Error updating user ${req.params.id}:`, {
                    message: updateError.message,
                    stack: updateError.stack,
                    error: updateError,
                    updates
                });
                if (updateError.code === 11000) {
                    const field = Object.keys(updateError.keyPattern)[0];
                    logger.warn(`Duplicate key error during update for field: ${field}`, {field, updates});
                    return res.status(400).json({
                        success: false,
                        message: `${field} already exists. Please use a different ${field}.`,
                        timestamp: new Date().toISOString()
                    });
                }
                return res.status(500).json({
                    success: false,
                    message: `Error updating user: ${updateError.message}`,
                    timestamp: new Date().toISOString()
                });
            }
            if (!updatedUser) {
                logger.warn(`${logger.safeColor(logger.colors.yellow)}[User Controller]${logger.safeColor(logger.colors.reset)} User not found or update failed for user: ${req.params.id}`);
                return res.status(404).json({
                    success: false,
                    message: 'User not found',
                    timestamp: new Date().toISOString()
                });
            }
            logger.info(`${logger.safeColor(logger.colors.green)}[User Controller]${logger.safeColor(logger.colors.reset)} User updated successfully: ${updatedUser._id}`, {updates});

            // Use comprehensive cache invalidation instead of manual cache operations
            await cache.invalidateAllRelatedCaches('user', userId, userId);

            // Check if role request was auto-approved during this update
            const roleRequestApproved = updates.roleApprovalStatus === 'APPROVED' && 
                                      updates.pendingRoles && 
                                      updates.pendingRoles.length === 0;

            const responseMessage = roleRequestApproved ? 
                'User updated successfully and pending role request auto-approved' : 
                'User updated successfully';

            return res.json({
                success: true,
                message: responseMessage,
                user: formatUserResponse(updatedUser),
                roleRequestAutoApproved: roleRequestApproved,
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            logger.error('Error in updateUser controller:', {
                message: error.message,
                stack: error.stack,
                error,
                userId: req.params.id
            });
            return res.status(500).json({
                success: false,
                message: `Error updating user: ${error.message}`
            });
        }
    }),

    // Delete a user
    deleteUser: asyncHandler(async (req, res, next) => {
        const userId = req.params.id;
        logger.info(`${logger.safeColor(logger.colors.cyan)}[User Controller]${logger.safeColor(logger.colors.reset)} Deleting user ${userId}`, {
            requestorId: req.user ? req.user.id : 'Unknown user',
            ip: req.ip
        });

        // Prevent user from deleting themselves
        if (req.user.id === userId) {
            logger.warn('Attempt to self-delete account', {userId});
            return res.status(400).json({
                success: false,
                message: 'You cannot delete your own account. Please contact another administrator.',
                timestamp: new Date().toISOString()
            });
        }

        try {
            if (!req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
                logger.warn('Invalid user ID format for delete', {userId: req.params.id});
                return res.status(400).json({
                    success: false,
                    message: 'Invalid user ID format',
                    timestamp: new Date().toISOString()
                });
            }

            const isDeletingOtherUser = req.user.id !== req.params.id;
            if (isDeletingOtherUser && !hasRight(req.user.roles, RIGHTS.DELETE_USERS)) {
                logger.warn('Forbidden: User attempting to delete another user without DELETE_USERS right', {
                    requestorId: req.user.id,
                    targetUserId: req.params.id
                });
                return res.status(403).json({
                    success: false,
                    message: 'Forbidden: You do not have permission to delete other users',
                    timestamp: new Date().toISOString()
                });
            }

            const userExists = await User.findById(req.params.id);
            if (!userExists) {
                logger.warn(`${logger.safeColor(logger.colors.yellow)}[User Controller]${logger.safeColor(logger.colors.reset)} User not found for delete: ${req.params.id}`);
                return res.status(404).json({
                    success: false,
                    message: 'User not found',
                    timestamp: new Date().toISOString()
                });
            }

            const result = await User.deleteOne({_id: req.params.id});

            if (result.deletedCount === 0) {
                logger.warn(`User could not be deleted: ${req.params.id}`);
                return res.status(404).json({
                    success: false,
                    message: 'User could not be deleted',
                    timestamp: new Date().toISOString()
                });
            }
            logger.info(`${logger.safeColor(logger.colors.green)}[User Controller]${logger.safeColor(logger.colors.reset)} User deleted successfully: ${req.params.id}`);

            await cache.invalidateUserCaches(userId); // Use helper for comprehensive cache invalidation

            return res.json({
                success: true,
                message: 'User deleted successfully',
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            logger.error('Error in deleteUser controller:', {
                message: error.message,
                stack: error.stack,
                error,
                userId: req.params.id
            });
            return res.status(500).json({
                success: false,
                message: `Error deleting user: ${error.message}`,
                timestamp: new Date().toISOString()
            });
        }
    }),    // Change password
    changePassword: asyncHandler(async (req, res) => {
        logger.info(`${logger.safeColor(logger.colors.cyan)}[User Controller]${logger.safeColor(logger.colors.reset)} Changing password for user ${req.params.id}`, {
            requestorId: req.user ? req.user.id : 'Unknown user',
            ip: req.ip
        });

        const user = await User.findById(req.params.id).select('+password +passwordHistory');
        if (!user) {
            logger.warn(`User not found for password change: ${req.params.id}`);
            return res.status(404).json({
                success: false,
                message: 'User not found',
                timestamp: new Date().toISOString()
            });
        }

        // Extract passwords directly from request body for authentication
        // Note: We don't sanitize here as we need actual passwords for verification
        const {currentPassword, newPassword} = req.body;

        // Log sanitized version for security (without actual sensitive data)
        const sanitizedData = sanitizeObject(req.body);
        logger.info(`${logger.safeColor(logger.colors.cyan)}[User Controller]${logger.safeColor(logger.colors.reset)} Password change attempt`, {
            sanitizedData,
            userId: req.params.id
        });

        // Check if user is changing their own password or if admin is resetting
        const isOwnPassword = req.user.id === req.params.id;
        const isAdmin = hasRight(req.user.roles, RIGHTS.MANAGE_ALL_USERS);

        // Validate required fields based on permission
        if (isOwnPassword && !currentPassword) {
            logger.warn('Current password required for self password change', {userId: req.params.id});
            return res.status(400).json({
                success: false,
                message: 'Current password is required to change your own password',
                timestamp: new Date().toISOString()
            });
        }

        if (!newPassword) {
            logger.warn('New password is required for password change', {userId: req.params.id});
            return res.status(400).json({
                success: false,
                message: 'New password is required',
                timestamp: new Date().toISOString()
            });
        }

        // Verify current password if provided (for own password changes)
        if (currentPassword && isOwnPassword) {
            const isMatch = await bcrypt.compare(currentPassword, user.password);
            if (!isMatch) {
                logger.warn('Invalid current password during password change attempt', {userId: req.params.id});
                return res.status(400).json({
                    success: false,
                    message: 'Invalid current password'
                });
            }
        }

        // Check if the new password was previously used (last 5 passwords)
        const wasPasswordUsed = await user.isPasswordPreviouslyUsed(newPassword);
        if (wasPasswordUsed) {
            logger.warn('Password change: Password was previously used', {userId: req.params.id});
            return res.status(400).json({
                success: false,
                message: 'This password was recently used. Please choose a different password.',
                timestamp: new Date().toISOString()
            });
        }

        // Check if new password is the same as current password
        const isSameAsCurrent = await bcrypt.compare(newPassword, user.password);
        if (isSameAsCurrent) {
            logger.warn('Password change: New password same as current', {userId: req.params.id});
            return res.status(400).json({
                success: false,
                message: 'New password cannot be the same as your current password.',
                timestamp: new Date().toISOString()
            });
        }

        // For admin password resets, log the action for security audit
        if (!isOwnPassword && isAdmin) {
            logger.info(`${logger.safeColor(logger.colors.cyan)}[User Controller]${logger.safeColor(logger.colors.reset)} Admin password reset performed`, {
                adminId: req.user.id,
                adminUsername: req.user.username,
                targetUserId: req.params.id,
                targetUsername: user.username,
                ip: req.ip
            });
        }

        // Add current password to history before changing
        user.addPasswordToHistory(user.password);

        // Update password (newPassword is already hashed by middleware)
        user.password = req.body.password; // Use the hashed password from middleware
        await user.save();

        // Clear user caches after password change
        await cache.invalidateUserCaches(req.params.id); // Use helper for comprehensive cache invalidation

        // Send notification email for admin password resets
        if (!isOwnPassword && isAdmin) {
            try {
                await sendPasswordChangedEmail(user);
                logger.info(`Password change notification email sent for user: ${req.params.id}`);
            } catch (emailError) {
                logger.warn(`Failed to send password change notification email: ${emailError.message}`, {
                    userId: req.params.id,
                    error: emailError
                });
                // Don't fail the password change if email fails
            }
        }

        logger.info(`${logger.safeColor(logger.colors.green)}[User Controller]${logger.safeColor(logger.colors.reset)} Password updated successfully for user: ${req.params.id}`);

        return res.status(200).json({
            success: true,
            message: 'Password updated successfully',
            meta: {
                timestamp: new Date().toISOString()
            }
        });
    }),

    // Get user's files with filtering and pagination
    getUserFiles: asyncHandler(async (req, res) => {
        try {
            const userId = req.params.id;
            const currentUserId = req.user.id;
            const currentUserRoles = req.user.roles || [];

            // Check if user is requesting their own files or has admin privileges
            const isOwnFiles = userId === currentUserId;
            const isAdmin = hasRight(currentUserRoles, RIGHTS.MANAGE_ALL_USERS);

            if (!isOwnFiles && !isAdmin) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied. You can only view your own files unless you have admin privileges.'
                });
            }

            // Parse filters and options using the universal filter system
            const {filters, options} = parseFilters(req.query);

            // Ensure we only get files for the specified user
            filters.owner = new mongoose.Types.ObjectId(userId);

            // Additional pipeline stages for file-specific aggregation
            const additionalPipeline = [
                // Get latest version of each file only
                {$sort: {filePath: 1, owner: 1, version: -1}},
                {
                    $group: {
                        _id: {filePath: '$filePath', owner: '$owner'},
                        latestVersion: {$first: '$$ROOT'}
                    }
                },
                {$replaceRoot: {newRoot: '$latestVersion'}}
            ];

            // Apply the filters using aggregation (for complex file operations)
            const files = await applyFiltersToAggregation(File, filters, options, additionalPipeline);

            // Get total count for pagination
            const totalCountPipeline = [
                {$match: filters},
                {$sort: {filePath: 1, owner: 1, version: -1}},
                {$group: {_id: {filePath: '$filePath', owner: '$owner'}}},
                {$count: 'total'}
            ];

            const totalResult = await File.aggregate(totalCountPipeline);
            const totalFiles = totalResult[0]?.total || 0;

            // Populate owner information
            await File.populate(files, {
                path: 'owner lastModifiedBy',
                select: 'firstName lastName username email'
            });

            // Get filter summary for response metadata
            const filterSummary = getFilterSummary(filters, options);

            logger.info(`Retrieved ${files.length} files for user ${userId}`, {
                requesterId: req.user.id,
                isOwnFiles,
                isAdmin,
                pagination: {
                    currentPage: filterSummary.pagination?.page || 1,
                    totalPages: filterSummary.pagination ? Math.ceil(totalFiles / filterSummary.pagination.limit) : 1,
                    totalFiles,
                    hasNextPage: filterSummary.pagination && filterSummary.pagination.page < Math.ceil(totalFiles / filterSummary.pagination.limit),
                    hasPrevPage: filterSummary.pagination && filterSummary.pagination.page > 1,
                    limit: filterSummary.pagination?.limit || 50
                },
                filters: filterSummary
            });

            const response = {
                success: true,
                message: 'User files retrieved successfully',
                files,
                meta: {
                    userId,
                    pagination: {
                        currentPage: filterSummary.pagination?.page || 1,
                        totalPages: filterSummary.pagination ? Math.ceil(totalFiles / filterSummary.pagination.limit) : 1,
                        totalFiles,
                        hasNextPage: filterSummary.pagination && filterSummary.pagination.page < Math.ceil(totalFiles / filterSummary.pagination.limit),
                        hasPrevPage: filterSummary.pagination && filterSummary.pagination.page > 1,
                        limit: filterSummary.pagination?.limit || 50
                    },
                    filters: filterSummary,
                    summary: {
                        totalFiles,
                        totalSize: files.reduce((total, file) => total + file.size, 0),
                        fileTypes: [...new Set(files.map(file => file.type).filter(Boolean))],
                        inlineStorage: files.filter(file => file.storageType === 'inline').reduce((total, file) => total + file.size, 0),
                        gridfsStorage: files.filter(file => file.storageType === 'gridfs').reduce((total, file) => total + file.size, 0),
                        storageBreakdown: [
                            {
                                type: 'inline',
                                size: files.filter(file => file.storageType === 'inline').reduce((total, file) => total + file.size, 0)
                            },
                            {
                                type: 'gridfs',
                                size: files.filter(file => file.storageType === 'gridfs').reduce((total, file) => total + file.size, 0)
                            }
                        ].filter(item => item.size > 0)
                    },
                    timestamp: new Date().toISOString()
                }
            };

            res.status(200).json(response);
        } catch (error) {
            if (error instanceof AppError) throw error;
            logger.error('Get user files error:', {
                message: error.message,
                userId: req.params.id,
                requesterId: req.user.id
            });
            throw new AppError('Error retrieving user files', 500);
        }
    }),

    /**
     * @desc    Get user statistics
     * @route   GET /api/v1/users/:id/stats
     * @access  Owner, Admin, or Self (limited view)
     */
    getUserStats: asyncHandler(async (req, res, next) => {
        try {
            const userId = req.params.id;

            // Check if the requesting user has admin rights or is the user themselves
            const isAdmin = hasRight(req.user.roles, RIGHTS.MANAGE_ALL_USERS);
            const isSelf = req.user.id === userId;

            // Gather basic user information
            const user = await User.findById(userId).select('+active');
            if (!user) {
                return next(new AppError('User not found', 404));
            }

            // Calculate activity statistics
            const stats = {
                user: formatUserResponse(user),
                activity: {},
                files: {},
                security: {}
            };

            // Only include sensitive data for admins or self
            if (isAdmin || isSelf) {
                // Get default time filter (30 days) or use provided filters
                const defaultTimeFilter = {$gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)};
                const timeFilter = req.statsFilters?.createdAt || defaultTimeFilter;

                // Get login history (from Logs)
                const loginLogs = await Log.aggregate([
                    {
                        $match: {
                            userId: new mongoose.Types.ObjectId(userId),
                            statusCode: {$gte: 200, $lt: 300},
                            url: {$regex: 'login', $options: 'i'},
                            timestamp: timeFilter
                        }
                    },
                    {$sort: {timestamp: -1}},
                    {$limit: 10}
                ]);

                // Calculate activity metrics
                const activityLogs = await Log.aggregate([
                    {
                        $match: {
                            userId: new mongoose.Types.ObjectId(userId),
                            timestamp: timeFilter
                        }
                    },
                    {
                        $group: {
                            _id: {
                                operationType: {$ifNull: ['$operationType', 'OTHER']}
                            },
                            count: {$sum: 1},
                            avgResponseTime: {$avg: {$ifNull: ['$responseTime', 0]}}
                        }
                    },
                    {$sort: {count: -1}}
                ]);

                // Get file statistics (if File model exists)
                let fileStats = {};
                try {
                    const userObjectId = new mongoose.Types.ObjectId(userId);

                    // Count total files by user - use ObjectId for consistency
                    const totalFiles = await File.countDocuments({owner: userObjectId});

                    // Get file type distribution
                    const filesByType = await File.aggregate([
                        {$match: {owner: userObjectId}},
                        {$group: {_id: '$mimeType', count: {$sum: 1}}},
                        {$sort: {count: -1}},
                        {$limit: 10}
                    ]);

                    // Calculate total storage used (includes saved version sizes)
                    const storageUsed = await File.aggregate([
                        {$match: {owner: userObjectId}},
                        {$group: {_id: null, totalSize: {$sum: {$add: [
                            {$ifNull: ['$size', 0]},
                            {$sum: {$map: {input: {$ifNull: ['$versionHistory', []]}, as: 'v', in: {$ifNull: ['$$v.size', 0]}}}}
                        ]}}}}
                    ]);

                    fileStats = {
                        totalFiles,
                        filesByType: filesByType.map(item => ({
                            type: item._id || 'unknown',
                            count: item.count
                        })),
                        totalStorage: storageUsed.length > 0 ? storageUsed[0].totalSize : 0,
                        averageFileSize: totalFiles > 0 && storageUsed.length > 0 ?
                            Math.round(storageUsed[0].totalSize / totalFiles) : 0
                    };
                } catch (err) {
                    fileStats = {error: 'File statistics not available'};
                }

                // Populate the stats object with results
                stats.activity = {
                    lastLogin: loginLogs.length > 0 ? loginLogs[0].timestamp : null,
                    loginHistory: loginLogs.map(log => ({
                        timestamp: log.timestamp,
                        ip: log.ip,
                        userAgent: log.userAgent,
                        success: log.statusCode >= 200 && log.statusCode < 300
                    })),
                    activityBreakdown: activityLogs.map(log => ({
                        operation: log._id.operationType,
                        count: log.count,
                        avgResponseTime: Math.round(log.avgResponseTime * 100) / 100
                    }))
                };

                stats.files = fileStats;

                // Security-related information
                stats.security = {
                    accountCreated: user.createdAt,
                    lastPasswordChange: user.passwordChangedAt,
                    twoFactorEnabled: !!user.twoFactorEnabled,
                    active: !!user.active
                };
            } else {
                // Limited view for non-admins viewing other users
                stats.limited = true;
                delete stats.security;
                delete stats.activity;

                // Only include basic file stats
                try {
                    const userObjectId = new mongoose.Types.ObjectId(userId);
                    stats.files = {
                        totalFiles: await File.countDocuments({
                            owner: userObjectId,
                            isPublic: true // Only show count of public files
                        })
                    };
                } catch (err) {
                    stats.files = {error: 'File statistics not available'};
                }
            }

            logger.info(`User stats retrieved for user: ${userId}`, {
                requesterId: req.user.id,
                isAdmin,
                isSelf
            });

            res.status(200).json({
                success: true,
                message: 'User statistics retrieved successfully',
                stats,
                meta: {
                    timestamp: new Date().toISOString()
                }
            });
        } catch (error) {
            logger.error('Error retrieving user stats:', error);
            next(new AppError('Failed to retrieve user statistics', 500));
        }
    }),

    /**
     * @desc    Get specific user statistics fields
     * @route   GET /api/v1/users/:id/stats/fields
     * @access  Admin or Self (limited view for others)
     */
    getUserStatsFields: asyncHandler(async (req, res, next) => {
        try {
            const userId = req.params.id;
            const requestedFields = req.query.fields ? req.query.fields.split(',') : [];

            // Check permissions
            const isAdmin = hasRight(req.user.roles, RIGHTS.MANAGE_ALL_USERS);
            const isSelf = req.user.id === userId;

            // Verify user exists
            const user = await User.findById(userId).select('+active');
            if (!user) {
                return next(new AppError('User not found', 404));
            }

            // Initialize response object
            const result = {
                userId,
                requestedFields,
                data: {}
            };

            // Helper function to set nested property
            const setNestedProperty = (obj, path, value) => {
                const keys = path.split('.');
                let current = obj;
                for (let i = 0; i < keys.length - 1; i++) {
                    const key = keys[i];
                    if (!(key in current)) {
                        current[key] = {};
                    }
                    current = current[key];
                }
                current[keys[keys.length - 1]] = value;
            };

            // Helper function to check if field is allowed for current user
            const isFieldAllowed = (field) => {
                // Non-admin users viewing other users can only access limited fields
                if (!isAdmin && !isSelf) {
                    const allowedFields = [
                        'user.username',
                        'user.firstName',
                        'user.lastName',
                        'user.roles',
                        'user.createdAt',
                        'files.totalFiles' // Only public files count
                    ];
                    return allowedFields.some(allowed => field.startsWith(allowed));
                }
                return true;
            };

            // Get time filters
            const defaultTimeFilter = {$gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)};
            const timeFilter = req.statsFilters?.createdAt || defaultTimeFilter;

            // Process each requested field
            for (const field of requestedFields) {
                if (!isFieldAllowed(field)) {
                    setNestedProperty(result.data, field, {error: 'Access denied'});
                    continue;
                }

                try {
                    if (field.startsWith('user.')) {
                        const userField = field.replace('user.', '');
                        const formattedUser = formatUserResponse(user);
                        if (userField in formattedUser) {
                            setNestedProperty(result.data, field, formattedUser[userField]);
                        } else {
                            setNestedProperty(result.data, field, null);
                        }

                    } else if (field.startsWith('activity.')) {
                        const activityField = field.replace('activity.', '');

                        if (activityField === 'lastLogin') {
                            const lastLogin = await Log.findOne({
                                userId: new mongoose.Types.ObjectId(userId),
                                statusCode: {$gte: 200, $lt: 300},
                                url: {$regex: 'login', $options: 'i'}
                            }).sort({timestamp: -1});

                            setNestedProperty(result.data, field, lastLogin ? lastLogin.timestamp : null);

                        } else if (activityField === 'loginHistory') {
                            const limit = req.query.limit || 10;
                            const loginHistory = await Log.find({
                                userId: new mongoose.Types.ObjectId(userId),
                                statusCode: {$gte: 200, $lt: 300},
                                url: {$regex: 'login', $options: 'i'},
                                timestamp: timeFilter
                            })
                                .sort({timestamp: -1})
                                .limit(parseInt(limit))
                                .select('timestamp ip userAgent statusCode');

                            setNestedProperty(result.data, field, loginHistory.map(log => ({
                                timestamp: log.timestamp,
                                ip: log.ip,
                                userAgent: log.userAgent,
                                success: log.statusCode >= 200 && log.statusCode < 300
                            })));

                        } else if (activityField === 'activityBreakdown') {
                            const activityBreakdown = await Log.aggregate([
                                {
                                    $match: {
                                        userId: new mongoose.Types.ObjectId(userId),
                                        timestamp: timeFilter
                                    }
                                },
                                {
                                    $group: {
                                        _id: {
                                            operationType: {$ifNull: ['$operationType', 'OTHER']}
                                        },
                                        count: {$sum: 1},
                                        avgResponseTime: {$avg: {$ifNull: ['$responseTime', 0]}}
                                    }
                                },
                                {$sort: {count: -1}}
                            ]);

                            setNestedProperty(result.data, field, activityBreakdown.map(log => ({
                                operation: log._id.operationType,
                                count: log.count,
                                avgResponseTime: Math.round(log.avgResponseTime * 100) / 100
                            })));
                        }

                    } else if (field.startsWith('files.')) {
                        const fileField = field.replace('files.', '');

                        try {
                            const userObjectId = new mongoose.Types.ObjectId(userId);

                            // For non-admin/non-self, only show public files
                            const fileQuery = (!isAdmin && !isSelf) ?
                                {owner: userObjectId, isPublic: true} :
                                {owner: userObjectId};

                            if (fileField === 'totalFiles') {
                                const count = await File.countDocuments(fileQuery);
                                setNestedProperty(result.data, field, count);

                            } else if (fileField === 'filesByType') {
                                const filesByType = await File.aggregate([
                                    {$match: fileQuery},
                                    {$group: {_id: '$mimeType', count: {$sum: 1}}},
                                    {$sort: {count: -1}},
                                    {$limit: 10}
                                ]);

                                setNestedProperty(result.data, field, filesByType.map(item => ({
                                    type: item._id || 'unknown',
                                    count: item.count
                                })));

                            } else if (fileField === 'totalStorage' && (isAdmin || isSelf)) {
                                const storageResult = await File.aggregate([
                                    {$match: fileQuery},
                                    {$group: {_id: null, totalSize: {$sum: {$add: [
                                        {$ifNull: ['$size', 0]},
                                        {$sum: {$map: {input: {$ifNull: ['$versionHistory', []]}, as: 'v', in: {$ifNull: ['$$v.size', 0]}}}}
                                    ]}}}}
                                ]);

                                setNestedProperty(result.data, field,
                                    storageResult.length > 0 ? storageResult[0].totalSize : 0);

                            } else if (fileField === 'averageFileSize' && (isAdmin || isSelf)) {
                                const [totalFiles, storageResult] = await Promise.all([
                                    File.countDocuments(fileQuery),
                                    File.aggregate([
                                        {$match: fileQuery},
                                        {$group: {_id: null, totalSize: {$sum: {$add: [
                                            {$ifNull: ['$size', 0]},
                                            {$sum: {$map: {input: {$ifNull: ['$versionHistory', []]}, as: 'v', in: {$ifNull: ['$$v.size', 0]}}}}
                                        ]}}}}
                                    ])
                                ]);

                                const totalStorage = storageResult.length > 0 ? storageResult[0].totalSize : 0;
                                const avgSize = totalFiles > 0 ? Math.round(totalStorage / totalFiles) : 0;
                                setNestedProperty(result.data, field, avgSize);
                            }

                        } catch (err) {
                            setNestedProperty(result.data, field, {error: 'File statistics not available'});
                        }

                    } else if (field.startsWith('security.') && (isAdmin || isSelf)) {
                        const securityField = field.replace('security.', '');

                        const securityData = {
                            accountCreated: user.createdAt,
                            lastPasswordChange: user.passwordChangedAt,
                            twoFactorEnabled: !!user.twoFactorEnabled,
                            active: !!user.active
                        };

                        if (securityField in securityData) {
                            setNestedProperty(result.data, field, securityData[securityField]);
                        } else {
                            setNestedProperty(result.data, field, null);
                        }

                    } else if (field.startsWith('security.') && !isAdmin && !isSelf) {
                        setNestedProperty(result.data, field, {error: 'Access denied - security information restricted'});

                    } else {
                        setNestedProperty(result.data, field, {error: 'Unknown field'});
                    }

                } catch (fieldError) {
                    logger.error(`Error processing field ${field}:`, fieldError);
                    setNestedProperty(result.data, field, {error: 'Field processing error'});
                }
            }

            logger.info(`User stats fields retrieved for user: ${userId}`, {
                requesterId: req.user.id,
                isAdmin,
                isSelf,
                fields: requestedFields
            });

            res.status(200).json({
                success: true,
                ...result,
                timestamp: new Date().toISOString()
            });

        } catch (error) {
            logger.error('Error retrieving user stats fields:', error);
            next(new AppError('Failed to retrieve user statistics fields', 500));
        }
    }),

    /**
     * @desc    Get aggregate user statistics for all users
     * @route   GET /api/v1/users/stats/overview
     * @access  Admin only
     */
    getUsersOverviewStats: asyncHandler(async (req, res, next) => {
        try {

            // Initialize stats object
            const stats = {
                summary: {},
                activity: {},
                roles: {},
                timeline: {}
            };

            // Get user count statistics with active/inactive breakdown
            const userCountsByStatus = await User.aggregate([
                {
                    $group: {
                        _id: {$ifNull: ['$active', true]},
                        count: {$sum: 1}
                    }
                }
            ]);

            // Get user count by role
            const userCountsByRole = await User.aggregate([
                {$unwind: '$roles'},
                {
                    $group: {
                        _id: '$roles',
                        count: {$sum: 1}
                    }
                },
                {$sort: {count: -1}}
            ]);

            // Get user registration timeline (grouped by month)
            let timelinePeriod = 'month';
            if (req.query.groupBy === 'day') {
                timelinePeriod = 'day';
            } else if (req.query.groupBy === 'week') {
                timelinePeriod = 'week';
            }

            // Set time range for timeline
            const timeframeEnd = new Date();
            let timeframeStart = new Date();
            if (req.statsFilters && req.statsFilters.createdAt && req.statsFilters.createdAt.$gte) {
                timeframeStart = req.statsFilters.createdAt.$gte;
            } else {
                // Default to last 12 months
                timeframeStart.setFullYear(timeframeStart.getFullYear() - 1);
            }

            // Prepare timeline aggregation format string
            let timelineFormat;
            if (timelinePeriod === 'day') {
                timelineFormat = {$dateToString: {format: "%Y-%m-%d", date: "$createdAt"}};
            } else if (timelinePeriod === 'week') {
                timelineFormat = {
                    $dateToString: {
                        format: "%Y-W%U",
                        date: "$createdAt"
                    }
                };
            } else {
                timelineFormat = {$dateToString: {format: "%Y-%m", date: "$createdAt"}};
            }

            // Get user registration timeline
            const registrationTimeline = await User.aggregate([
                {
                    $match: {
                        createdAt: {$gte: timeframeStart, $lte: timeframeEnd}
                    }
                },
                {
                    $group: {
                        _id: timelineFormat,
                        count: {$sum: 1}
                    }
                },
                {$sort: {_id: 1}}
            ]);

            // Calculate system-wide activity metrics
            const activityMetrics = await Log.aggregate([
                {
                    $match: {
                        timestamp: {$gte: timeframeStart, $lte: timeframeEnd}
                    }
                },
                {
                    $group: {
                        _id: {
                            method: "$method"
                        },
                        count: {$sum: 1},
                        avgResponseTime: {$avg: "$responseTime"}
                    }
                },
                {$sort: {count: -1}}
            ]);

            // Get recent logins (successful)
            const recentLogins = await Log.aggregate([
                {
                    $match: {
                        method: 'POST',
                        url: {$regex: 'login', $options: 'i'},
                        statusCode: {$gte: 200, $lt: 300}
                    }
                },
                {$sort: {timestamp: -1}},
                {$limit: 10},
                {
                    $lookup: {
                        from: 'users',
                        localField: 'userId',
                        foreignField: '_id',
                        as: 'userInfo'
                    }
                },
                {
                    $project: {
                        timestamp: 1,
                        ip: 1,
                        userAgent: 1,
                        user: {$arrayElemAt: ['$userInfo', 0]}
                    }
                },
                {
                    $project: {
                        timestamp: 1,
                        ip: 1,
                        userAgent: 1,
                        username: '$user.username',
                        userId: '$user._id',
                    }
                }
            ]);

            // Populate stats object with results
            stats.summary = {
                totalUsers: userCountsByStatus.reduce((sum, item) => sum + item.count, 0),
                activeUsers: userCountsByStatus.find(item => item._id === true)?.count || 0,
                inactiveUsers: userCountsByStatus.find(item => item._id === false)?.count || 0,
                // Pre-calculate admin users count
                adminUsers: userCountsByRole
                    .filter(role => role._id === 'ADMIN' || role._id === 'OWNER')
                    .reduce((sum, role) => sum + role.count, 0)
            };

            // Calculate newThisWeek separately after getting the timeline data
            const weekAgo = new Date();
            weekAgo.setDate(weekAgo.getDate() - 7);

            // Get new users this week from raw user data (more accurate than timeline parsing)
            const newThisWeek = await User.countDocuments({
                createdAt: {$gte: weekAgo}
            });

            stats.summary.newThisWeek = newThisWeek;

            stats.roles = userCountsByRole.map(role => ({
                role: role._id,
                count: role.count,
                percentage: Math.round((role.count / stats.summary.totalUsers) * 100)
            }));

            stats.timeline = {
                period: timelinePeriod,
                data: registrationTimeline.map(item => ({
                    period: item._id,
                    count: item.count
                }))
            };

            stats.activity = {
                metrics: activityMetrics.map(item => ({
                    type: item._id.method,
                    count: item.count,
                    avgResponseTime: Math.round(item.avgResponseTime * 100) / 100
                })),
                recentLogins: recentLogins.map(login => ({
                    timestamp: login.timestamp,
                    username: login.username,
                    userId: login.userId,
                    ip: login.ip,
                    userAgent: login.userAgent
                }))
            };

            logger.info('User overview stats retrieved', {
                requesterId: req.user.id,
                timeframe: {start: timeframeStart, end: timeframeEnd}
            });

            res.status(200).json({
                success: true,
                message: 'User overview statistics retrieved successfully',
                overview: stats,
                meta: {
                    timeframe: {start: timeframeStart, end: timeframeEnd},
                    timestamp: new Date().toISOString()
                }
            });
        } catch (error) {
            logger.error('Error retrieving users overview stats:', error);
            next(new AppError('Failed to retrieve user overview statistics', 500));
        }
    }),

    // =========================================================================
    // CONNECTION ACTIONS (LinkedIn-style symmetric connections)
    // =========================================================================

    /**
     * @desc    Send a connection request to a user
     * @route   POST /api/v1/users/:id/connect
     * @access  Authenticated
     */
    sendConnectionRequest: asyncHandler(async (req, res, next) => {
        const requesterId = req.user.id;
        const recipientId = req.params.id;

        if (requesterId === recipientId) {
            return next(new AppError('You cannot connect with yourself', 400));
        }

        const targetUser = await User.findById(recipientId).select('_id');
        if (!targetUser) {
            return next(new AppError('User not found', 404));
        }

        // Check if a connection already exists in either direction
        const existing = await Connection.findOne({
            $or: [
                {requester: requesterId, recipient: recipientId},
                {requester: recipientId, recipient: requesterId}
            ]
        });

        if (existing) {
            if (existing.status === 'accepted') {
                return next(new AppError('You are already connected with this user', 400));
            }
            if (existing.status === 'pending') {
                // If the other user already sent us a request, auto-accept
                if (existing.requester.toString() === recipientId) {
                    existing.status = 'accepted';
                    await existing.save();

                    await Promise.all([
                        cache.del(`connections:${requesterId}`),
                        cache.del(`connections:${recipientId}`),
                        cache.del(`connections:pending:${requesterId}`),
                        cache.del(`connections:pending:${recipientId}`),
                        cache.del(`connections:sent:${requesterId}`),
                        cache.del(`connections:sent:${recipientId}`),
                        cache.del(`connections:counts:${requesterId}`),
                        cache.del(`connections:counts:${recipientId}`)
                    ]);

                    logger.info(`[Connection] ${requesterId} auto-accepted connection with ${recipientId}`);

                    return res.status(200).json({
                        success: true,
                        message: 'Connection request accepted (mutual request)'
                    });
                }
                return next(new AppError('Connection request already sent', 400));
            }
            if (existing.status === 'rejected') {
                // Allow re-requesting after rejection
                existing.status = 'pending';
                existing.requester = requesterId;
                existing.recipient = recipientId;
                await existing.save();

                await Promise.all([
                    cache.del(`connections:pending:${recipientId}`),
                    cache.del(`connections:sent:${requesterId}`),
                    cache.del(`connections:counts:${requesterId}`),
                    cache.del(`connections:counts:${recipientId}`)
                ]);

                logger.info(`[Connection] ${requesterId} re-sent connection request to ${recipientId}`);

                return res.status(200).json({
                    success: true,
                    message: 'Connection request sent'
                });
            }
        }

        await Connection.create({requester: requesterId, recipient: recipientId});

        await Promise.all([
            cache.del(`connections:pending:${recipientId}`),
            cache.del(`connections:sent:${requesterId}`),
            cache.del(`connections:counts:${requesterId}`),
            cache.del(`connections:counts:${recipientId}`)
        ]);

        logger.info(`[Connection] ${requesterId} sent connection request to ${recipientId}`);

        res.status(200).json({
            success: true,
            message: 'Connection request sent'
        });
    }),

    /**
     * @desc    Respond to a connection request (accept or reject)
     * @route   PUT /api/v1/users/:id/connect
     * @access  Authenticated
     */
    respondToConnection: asyncHandler(async (req, res, next) => {
        const currentUserId = req.user.id;
        const requesterId = req.params.id;
        const {action} = req.body;

        if (!['accept', 'reject'].includes(action)) {
            return next(new AppError('Action must be "accept" or "reject"', 400));
        }

        const connection = await Connection.findOne({
            requester: requesterId,
            recipient: currentUserId,
            status: 'pending'
        });

        if (!connection) {
            return next(new AppError('No pending connection request from this user', 404));
        }

        connection.status = action === 'accept' ? 'accepted' : 'rejected';
        await connection.save();

        await Promise.all([
            cache.del(`connections:${currentUserId}`),
            cache.del(`connections:${requesterId}`),
            cache.del(`connections:pending:${currentUserId}`),
            cache.del(`connections:sent:${requesterId}`),
            cache.del(`connections:counts:${currentUserId}`),
            cache.del(`connections:counts:${requesterId}`)
        ]);

        logger.info(`[Connection] ${currentUserId} ${action}ed request from ${requesterId}`);

        res.status(200).json({
            success: true,
            message: `Connection request ${action}ed`
        });
    }),

    /**
     * @desc    Remove a connection or cancel a sent request
     * @route   DELETE /api/v1/users/:id/connect
     * @access  Authenticated
     */
    removeConnection: asyncHandler(async (req, res, next) => {
        const currentUserId = req.user.id;
        const targetUserId = req.params.id;

        const result = await Connection.findOneAndDelete({
            $or: [
                {requester: currentUserId, recipient: targetUserId},
                {requester: targetUserId, recipient: currentUserId}
            ]
        });

        if (!result) {
            return next(new AppError('No connection found with this user', 400));
        }

        await Promise.all([
            cache.del(`connections:${currentUserId}`),
            cache.del(`connections:${targetUserId}`),
            cache.del(`connections:pending:${currentUserId}`),
            cache.del(`connections:pending:${targetUserId}`),
            cache.del(`connections:sent:${currentUserId}`),
            cache.del(`connections:sent:${targetUserId}`),
            cache.del(`connections:counts:${currentUserId}`),
            cache.del(`connections:counts:${targetUserId}`)
        ]);

        logger.info(`[Connection] ${currentUserId} removed connection with ${targetUserId}`);

        res.status(200).json({
            success: true,
            message: 'Connection removed'
        });
    }),

    /**
     * @desc    Get accepted connections for a user
     * @route   GET /api/v1/users/:id/connections
     * @access  Authenticated
     */
    getConnections: asyncHandler(async (req, res) => {
        const userId = req.params.id;
        const page = Math.max(1, parseInt(req.query.page, 10) || 1);
        const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
        const skip = (page - 1) * limit;

        const [connections, total] = await Promise.all([
            Connection.find({
                $or: [{requester: userId}, {recipient: userId}],
                status: 'accepted'
            })
                .sort({updatedAt: -1})
                .skip(skip)
                .limit(limit)
                .populate('requester', 'firstName lastName username email profilePhoto')
                .populate('recipient', 'firstName lastName username email profilePhoto'),
            Connection.countDocuments({
                $or: [{requester: userId}, {recipient: userId}],
                status: 'accepted'
            })
        ]);

        // Return the other user in each connection
        const data = connections.map(c => {
            return c.requester._id.toString() === userId ? c.recipient : c.requester;
        });

        res.status(200).json({
            success: true,
            data,
            pagination: {page, limit, total, pages: Math.ceil(total / limit)}
        });
    }),

    /**
     * @desc    Get pending incoming connection requests
     * @route   GET /api/v1/users/connections/pending
     * @access  Authenticated
     */
    getPendingRequests: asyncHandler(async (req, res) => {
        const userId = req.user.id;
        const page = Math.max(1, parseInt(req.query.page, 10) || 1);
        const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
        const skip = (page - 1) * limit;

        const [requests, total] = await Promise.all([
            Connection.find({recipient: userId, status: 'pending'})
                .sort({createdAt: -1})
                .skip(skip)
                .limit(limit)
                .populate('requester', 'firstName lastName username email profilePhoto'),
            Connection.countDocuments({recipient: userId, status: 'pending'})
        ]);

        res.status(200).json({
            success: true,
            data: requests.map(r => r.requester),
            pagination: {page, limit, total, pages: Math.ceil(total / limit)}
        });
    }),

    /**
     * @desc    Get sent outgoing connection requests
     * @route   GET /api/v1/users/connections/sent
     * @access  Authenticated
     */
    getSentRequests: asyncHandler(async (req, res) => {
        const userId = req.user.id;
        const page = Math.max(1, parseInt(req.query.page, 10) || 1);
        const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
        const skip = (page - 1) * limit;

        const [requests, total] = await Promise.all([
            Connection.find({requester: userId, status: 'pending'})
                .sort({createdAt: -1})
                .skip(skip)
                .limit(limit)
                .populate('recipient', 'firstName lastName username email profilePhoto'),
            Connection.countDocuments({requester: userId, status: 'pending'})
        ]);

        res.status(200).json({
            success: true,
            data: requests.map(r => r.recipient),
            pagination: {page, limit, total, pages: Math.ceil(total / limit)}
        });
    }),

    /**
     * @desc    Get connection counts for a user
     * @route   GET /api/v1/users/:id/connection-counts
     * @access  Authenticated
     */
    getConnectionCounts: asyncHandler(async (req, res) => {
        const userId = req.params.id;

        const [connectionCount, pendingCount] = await Promise.all([
            Connection.countDocuments({
                $or: [{requester: userId}, {recipient: userId}],
                status: 'accepted'
            }),
            Connection.countDocuments({recipient: userId, status: 'pending'})
        ]);

        res.status(200).json({
            success: true,
            data: {connectionCount, pendingCount}
        });
    }),

    /**
     * @desc    Check connection status with a user
     * @route   GET /api/v1/users/:id/connection-status
     * @access  Authenticated
     */
    getConnectionStatus: asyncHandler(async (req, res) => {
        const currentUserId = req.user.id;
        const targetUserId = req.params.id;

        const connection = await Connection.findOne({
            $or: [
                {requester: currentUserId, recipient: targetUserId},
                {requester: targetUserId, recipient: currentUserId}
            ]
        });

        let status = 'none';
        if (connection) {
            if (connection.status === 'accepted') {
                status = 'connected';
            } else if (connection.status === 'pending') {
                status = connection.requester.toString() === currentUserId ? 'pending_sent' : 'pending_received';
            } else if (connection.status === 'rejected') {
                status = 'rejected';
            }
        }

        res.status(200).json({
            success: true,
            data: {
                status,
                isConnected: connection?.status === 'accepted'
            }
        });
    }),

    // =========================================================================
    // GROUP OPERATIONS
    // =========================================================================

    /**
     * @desc    Create a new group
     * @route   POST /api/v1/groups
     * @access  Authenticated
     */
    createGroup: asyncHandler(async (req, res) => {
        const {name, description, privacy} = req.body;
        const userId = req.user.id;

        const group = await Group.create({
            name: sanitizeHtmlInput(name),
            description: description ? sanitizeHtmlInput(description) : undefined,
            privacy: privacy || 'private',
            createdBy: userId,
            members: [{user: userId, role: GROUP_ROLES.OWNER}]
        });

        // Derive a URL-safe slug from the group name.
        // The slug becomes the folder path and the URL segment — no IDs exposed.
        const slug = group.name
            .toLowerCase()
            .replace(/\s+/g, '-')
            .replace(/[^a-z0-9-]/g, '')
            .replace(/-+/g, '-')
            .replace(/^-|-$/g, '') || 'group';

        // Ensure the slug is unique across all root-level directories
        let groupFolder = `/${slug}`;
        const collision = await File.findOne({filePath: groupFolder, type: 'directory'});
        if (collision) groupFolder = `/${slug}-${group._id.toString().slice(-6)}`;

        await File.create({
            filePath: groupFolder,
            fileName: group.name,
            type: 'directory',
            mimeType: 'inode/directory',
            parentPath: '/',
            depth: 1,
            description: `Group folder: ${group.name}`,
            owner: userId,
            lastModifiedBy: userId,
            permissions: {read: [], write: []},
            size: 0
        });

        group.rootFolderPath = groupFolder;
        await group.save();

        await cache.del(`groups:user:${userId}`);

        logger.info(`[Group] Group "${group.name}" created by ${userId}, folder at ${groupFolder}`);

        res.status(201).json({
            success: true,
            data: group
        });
    }),

    /**
     * @desc    Get group by ID
     * @route   GET /api/v1/groups/:groupId
     * @access  Members / public groups
     */
    getGroup: asyncHandler(async (req, res, next) => {
        const group = req.group; // set by loadGroup middleware

        // Populate member user details
        await group.populate('members.user', 'firstName lastName username email profilePhoto');

        res.status(200).json({
            success: true,
            data: group
        });
    }),

    /**
     * @desc    Update group details (name, description, privacy, avatar)
     * @route   PATCH /api/v1/groups/:groupId
     * @access  Group ADMIN+
     */
    updateGroup: asyncHandler(async (req, res, next) => {
        const group = req.group;
        const {name, description, privacy, avatar} = req.body;

        if (name !== undefined) group.name = sanitizeHtmlInput(name);
        if (description !== undefined) group.description = sanitizeHtmlInput(description);
        if (privacy !== undefined) group.privacy = privacy;
        if (avatar !== undefined) group.avatar = avatar;

        // If the name changed, rename the group folder and cascade-update all nested paths.
        if (name !== undefined && group.rootFolderPath) {
            const newSlug = group.name
                .toLowerCase()
                .replace(/\s+/g, '-')
                .replace(/[^a-z0-9-]/g, '')
                .replace(/-+/g, '-')
                .replace(/^-|-$/g, '') || 'group';
            const newPath = `/${newSlug}`;
            const oldPath = group.rootFolderPath;

            if (oldPath !== newPath) {
                // Check for collision before renaming
                const collision = await File.findOne({filePath: newPath, type: 'directory'});
                if (collision) return next(new AppError(`Folder path ${newPath} is already in use`, 409));

                const escapedOld = oldPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                // Cascade rename: replace old prefix in filePath and parentPath
                await File.updateMany(
                    {filePath: {$regex: `^${escapedOld}(/|$)`}},
                    [{$set: {
                        filePath:   {$replaceAll: {input: '$filePath',   find: oldPath, replacement: newPath}},
                        parentPath: {$replaceAll: {input: '$parentPath', find: oldPath, replacement: newPath}}
                    }}]
                );
                group.rootFolderPath = newPath;
            }

            // Keep fileName in sync with current display name
            await File.updateOne(
                {filePath: group.rootFolderPath, type: 'directory'},
                {$set: {fileName: group.name}}
            );
        }

        await group.save();
        await cache.del(`groups:detail:${group._id}`);

        res.status(200).json({
            success: true,
            data: group
        });
    }),

    /**
     * @desc    Delete a group
     * @route   DELETE /api/v1/groups/:groupId
     * @access  Group OWNER only
     */
    deleteGroup: asyncHandler(async (req, res, next) => {
        const group = req.group;
        const userId = req.user.id;

        if (!group.hasMinRole(userId, GROUP_ROLES.OWNER)) {
            return next(new AppError('Only the group owner can delete the group', 403));
        }

        // Cascade-delete all File records inside the group's root folder
        if (group.rootFolderPath) {
            // Escape any regex special chars in the path before building the prefix regex
            const escapedPath = group.rootFolderPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            await File.deleteMany({
                $or: [
                    {filePath: group.rootFolderPath},
                    {filePath: {$regex: `^${escapedPath}/`}}
                ]
            });
        }

        // Invalidate caches for all members
        const memberIds = group.members.map(m => m.user);
        await Group.findByIdAndDelete(group._id);

        await Promise.all(
            memberIds.map(id => cache.del(`groups:user:${id}`))
        );
        await cache.del(`groups:detail:${group._id}`);

        logger.info(`[Group] Group "${group.name}" deleted by ${userId}`);

        res.status(200).json({
            success: true,
            message: 'Group deleted successfully'
        });
    }),

    /**
     * @desc    List groups the current user belongs to
     * @route   GET /api/v1/groups
     * @access  Authenticated
     */
    getMyGroups: asyncHandler(async (req, res) => {
        const userId = req.user.id;
        const page = Math.max(1, parseInt(req.query.page, 10) || 1);
        const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
        const skip = (page - 1) * limit;

        const filter = {'members.user': userId};
        const [groups, total] = await Promise.all([
            Group.find(filter)
                .sort({updatedAt: -1})
                .skip(skip)
                .limit(limit)
                .populate('members.user', 'firstName lastName username profilePhoto'),
            Group.countDocuments(filter)
        ]);

        res.status(200).json({
            success: true,
            data: groups,
            pagination: {page, limit, total, pages: Math.ceil(total / limit)}
        });
    }),

    /**
     * @desc    Discover public groups
     * @route   GET /api/v1/groups/discover
     * @access  Authenticated
     */
    discoverGroups: asyncHandler(async (req, res) => {
        const page = Math.max(1, parseInt(req.query.page, 10) || 1);
        const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
        const skip = (page - 1) * limit;
        const search = req.query.search;

        const filter = {privacy: 'public'};
        if (search) {
            // Escape regex special characters to prevent ReDoS / injection
            const escaped = search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            filter.name = {$regex: escaped, $options: 'i'};
        }

        const [groups, total] = await Promise.all([
            Group.find(filter)
                .sort({memberCount: -1, createdAt: -1})
                .skip(skip)
                .limit(limit)
                .select('name description avatar privacy memberCount fileCount createdAt'),
            Group.countDocuments(filter)
        ]);

        res.status(200).json({
            success: true,
            data: groups,
            pagination: {page, limit, total, pages: Math.ceil(total / limit)}
        });
    }),

    // =========================================================================
    // GROUP MEMBER MANAGEMENT
    // =========================================================================

    /**
     * @desc    Add a member to a group
     * @route   POST /api/v1/groups/:groupId/members
     * @access  Group ADMIN+
     */
    addMember: asyncHandler(async (req, res, next) => {
        const group = req.group;
        const {userId, role} = req.body;

        // Verify target user exists
        const targetUser = await User.findById(userId).select('_id');
        if (!targetUser) {
            return next(new AppError('User not found', 404));
        }

        // Check if already a member
        if (group.isMember(userId)) {
            return next(new AppError('User is already a member of this group', 400));
        }

        // Only WRITE or READ can be assigned directly; OWNER is only via transfer
        const assignedRole = role || GROUP_ROLES.READ;
        if (assignedRole === GROUP_ROLES.OWNER) {
            return next(new AppError('Cannot directly assign OWNER role. Use ownership transfer.', 403));
        }

        group.members.push({user: userId, role: assignedRole});
        await group.save();

        // Propagate role to ALL files under the group folder (not just the root)
        if (group.rootFolderPath) {
            const addField  = assignedRole === GROUP_ROLES.WRITE ? 'permissions.write' : 'permissions.read';
            const pullField = assignedRole === GROUP_ROLES.WRITE ? 'permissions.read'  : 'permissions.write';
            const uid = new mongoose.Types.ObjectId(userId);
            const escaped = group.rootFolderPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            await File.updateMany(
                {filePath: {$regex: `^${escaped}(/|$)`}},
                {$addToSet: {[addField]: uid}, $pull: {[pullField]: uid}}
            );
        }

        await Promise.all([
            cache.del(`groups:detail:${group._id}`),
            cache.del(`groups:user:${userId}`)
        ]);

        logger.info(`[Group] User ${userId} added to group ${group._id} as ${assignedRole}`);

        res.status(200).json({
            success: true,
            message: 'Member added successfully'
        });
    }),

    /**
     * @desc    Remove a member from a group
     * @route   DELETE /api/v1/groups/:groupId/members/:userId
     * @access  Group ADMIN+ or self
     */
    removeMember: asyncHandler(async (req, res, next) => {
        const group = req.group;
        const targetUserId = req.params.userId;
        const actorId = req.user.id;

        const targetMember = group.members.find(m => m.user.equals(targetUserId));
        if (!targetMember) {
            return next(new AppError('User is not a member of this group', 404));
        }

        // Owner cannot be removed
        if (targetMember.role === GROUP_ROLES.OWNER) {
            return next(new AppError('The group owner cannot be removed', 403));
        }

        // Self-removal is always allowed (except owner); only OWNER can remove others
        const isSelf = actorId === targetUserId;
        if (!isSelf && !group.hasMinRole(actorId, GROUP_ROLES.OWNER)) {
            return next(new AppError('Only the group owner can remove other members', 403));
        }

        group.members = group.members.filter(m => !m.user.equals(targetUserId));
        await group.save();

        // Remove from ALL files under the group folder
        if (group.rootFolderPath) {
            const uid = new mongoose.Types.ObjectId(targetUserId);
            const escaped = group.rootFolderPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            await File.updateMany(
                {filePath: {$regex: `^${escaped}(/|$)`}},
                {$pull: {'permissions.read': uid, 'permissions.write': uid}}
            );
        }

        await Promise.all([
            cache.del(`groups:detail:${group._id}`),
            cache.del(`groups:user:${targetUserId}`)
        ]);

        res.status(200).json({
            success: true,
            message: isSelf ? 'You have left the group' : 'Member removed successfully'
        });
    }),

    /**
     * @desc    Update a member's role
     * @route   PATCH /api/v1/groups/:groupId/members/:userId
     * @access  Group OWNER (for admin promotion), ADMIN+ for lower roles
     */
    updateMemberRole: asyncHandler(async (req, res, next) => {
        const group = req.group;
        const targetUserId = req.params.userId;
        const {role: newRole} = req.body;

        // Only WRITE or READ can be assigned; OWNER is set via transfer only
        if (![GROUP_ROLES.WRITE, GROUP_ROLES.READ].includes(newRole)) {
            return next(new AppError('Role must be WRITE or READ', 400));
        }

        const targetMember = group.members.find(m => m.user.equals(targetUserId));
        if (!targetMember) {
            return next(new AppError('User is not a member of this group', 404));
        }

        // Cannot change owner's role
        if (targetMember.role === GROUP_ROLES.OWNER) {
            return next(new AppError('Cannot change the owner\'s role', 403));
        }

        targetMember.role = newRole;
        await group.save();

        // Move user between permission arrays across ALL files under the group folder
        if (group.rootFolderPath) {
            const uid       = new mongoose.Types.ObjectId(targetUserId);
            const addField  = newRole === GROUP_ROLES.WRITE ? 'permissions.write' : 'permissions.read';
            const pullField = newRole === GROUP_ROLES.WRITE ? 'permissions.read'  : 'permissions.write';
            const escaped = group.rootFolderPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            await File.updateMany(
                {filePath: {$regex: `^${escaped}(/|$)`}},
                {$addToSet: {[addField]: uid}, $pull: {[pullField]: uid}}
            );
        }

        await cache.del(`groups:detail:${group._id}`);

        res.status(200).json({
            success: true,
            message: `Member role updated to ${newRole}`
        });
    }),

    /**
     * @desc    Join a public group
     * @route   POST /api/v1/groups/:groupId/join
     * @access  Authenticated
     */
    joinGroup: asyncHandler(async (req, res, next) => {
        const group = req.group;
        const userId = req.user.id;

        if (group.privacy !== 'public') {
            return next(new AppError('This group is private. You need an invite to join.', 403));
        }

        if (group.isMember(userId)) {
            return next(new AppError('You are already a member of this group', 400));
        }

        group.members.push({user: userId, role: GROUP_ROLES.READ});
        await group.save();

        // Grant read access on ALL files under the group folder
        if (group.rootFolderPath) {
            const uid = new mongoose.Types.ObjectId(userId);
            const escaped = group.rootFolderPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            await File.updateMany(
                {filePath: {$regex: `^${escaped}(/|$)`}},
                {$addToSet: {'permissions.read': uid}}
            );
        }

        await Promise.all([
            cache.del(`groups:detail:${group._id}`),
            cache.del(`groups:user:${userId}`)
        ]);

        res.status(200).json({
            success: true,
            message: 'Joined group successfully'
        });
    }),

    /**
     * @desc    Leave a group (alias for self-removal)
     * @route   POST /api/v1/groups/:groupId/leave
     * @access  Authenticated member
     */
    leaveGroup: asyncHandler(async (req, res, next) => {
        const group = req.group;
        const userId = req.user.id;

        const member = group.members.find(m => m.user.equals(userId));
        if (!member) {
            return next(new AppError('You are not a member of this group', 400));
        }

        if (member.role === GROUP_ROLES.OWNER) {
            return next(new AppError('Group owners cannot leave. Transfer ownership or delete the group.', 403));
        }

        group.members = group.members.filter(m => !m.user.equals(userId));
        await group.save();

        // Revoke permissions on ALL files under the group folder
        if (group.rootFolderPath) {
            const uid = new mongoose.Types.ObjectId(userId);
            const escaped = group.rootFolderPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            await File.updateMany(
                {filePath: {$regex: `^${escaped}(/|$)`}},
                {$pull: {'permissions.read': uid, 'permissions.write': uid}}
            );
        }

        await Promise.all([
            cache.del(`groups:detail:${group._id}`),
            cache.del(`groups:user:${userId}`)
        ]);

        res.status(200).json({
            success: true,
            message: 'You have left the group'
        });
    }),

    /**
     * @desc    Transfer group ownership
     * @route   PATCH /api/v1/groups/:groupId/transfer
     * @access  Group OWNER only
     */
    transferOwnership: asyncHandler(async (req, res, next) => {
        const group = req.group;
        const actorId = req.user.id;
        const {userId: newOwnerId} = req.body;

        if (!group.hasMinRole(actorId, GROUP_ROLES.OWNER)) {
            return next(new AppError('Only the group owner can transfer ownership', 403));
        }

        const newOwnerMember = group.members.find(m => m.user.equals(newOwnerId));
        if (!newOwnerMember) {
            return next(new AppError('Target user must be a member of the group', 400));
        }

        // Demote current owner to WRITE, promote new owner
        const currentOwner = group.members.find(m => m.user.equals(actorId));
        currentOwner.role = GROUP_ROLES.WRITE;
        newOwnerMember.role = GROUP_ROLES.OWNER;
        await group.save();

        // New owner gets write access across ALL files under the group folder
        if (group.rootFolderPath) {
            const uid = new mongoose.Types.ObjectId(newOwnerId);
            const escaped = group.rootFolderPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            await File.updateMany(
                {filePath: {$regex: `^${escaped}(/|$)`}},
                {$addToSet: {'permissions.write': uid}, $pull: {'permissions.read': uid}}
            );
        }

        await cache.del(`groups:detail:${group._id}`);

        logger.info(`[Group] Ownership of group ${group._id} transferred from ${actorId} to ${newOwnerId}`);

        res.status(200).json({
            success: true,
            message: 'Ownership transferred successfully'
        });
    }),

    // =========================================================================
    // STARRED FILES
    // =========================================================================

    /**
     * @desc    Get current user's starred files
     * @route   GET /api/v1/users/starred
     * @access  Authenticated
     */
    getStarredFiles: asyncHandler(async (req, res, next) => {
        const userId = req.user.id;

        const user = await User.findById(userId).populate({
            path: 'starredFiles',
            select: 'fileName filePath type mimeType size owner updatedAt',
            populate: { path: 'owner', select: 'username firstName lastName' }
        });

        if (!user) {
            return next(new AppError('User not found', 404));
        }

        // Filter out any files that no longer exist (deleted files)
        const validFiles = user.starredFiles.filter(f => f != null);

        res.status(200).json({
            success: true,
            data: validFiles
        });
    }),

    /**
     * @desc    Star (favorite) a file
     * @route   POST /api/v1/users/starred/:fileId
     * @access  Authenticated (must have read access to the file)
     */
    starFile: asyncHandler(async (req, res, next) => {
        const userId = req.user.id;
        const { fileId } = req.params;

        // Verify the file exists and user has access
        const file = await File.findById(fileId);
        if (!file) {
            return next(new AppError('File not found', 404));
        }

        if (!file.hasReadAccess(userId, req.user.roles)) {
            return next(new AppError('You do not have access to this file', 403));
        }

        // Add to starred files (only if not already starred)
        await User.findByIdAndUpdate(userId, {
            $addToSet: { starredFiles: fileId }
        });

        await cache.del(`user:starred:${userId}`);

        res.status(200).json({
            success: true,
            message: 'File starred'
        });
    }),

    /**
     * @desc    Unstar (unfavorite) a file
     * @route   DELETE /api/v1/users/starred/:fileId
     * @access  Authenticated
     */
    unstarFile: asyncHandler(async (req, res, next) => {
        const userId = req.user.id;
        const { fileId } = req.params;

        await User.findByIdAndUpdate(userId, {
            $pull: { starredFiles: fileId }
        });

        await cache.del(`user:starred:${userId}`);

        res.status(200).json({
            success: true,
            message: 'File unstarred'
        });
    })
};

export {userController, formatUserResponse, formatPublicUserResponse};
export default userController;
