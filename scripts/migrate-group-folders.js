/**
 * Migration: move group root folders from /groups/{id} (or /groups/{name}) to /{slug}.
 *
 * Old structure:
 *   filePath:   /groups/{mongoId}  OR  /groups/{name}  (root of group files)
 *   parentPath: /groups  OR  /
 *
 * New structure:
 *   filePath:   /{slug}   (slug derived from group.name)
 *   parentPath: /
 *   fileName:   {group.name}
 *
 * All nested files (parentPath / filePath starting with oldRoot) are updated too.
 * The /groups container node is removed.
 *
 * Usage:
 *   node --env-file=.env scripts/migrate-group-folders.js
 */

import mongoose from 'mongoose';
import { fileURLToPath } from 'url';

// ── Connect ──────────────────────────────────────────────────────────────────
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) { console.error('MONGODB_URI required'); process.exit(1); }

await mongoose.connect(MONGODB_URI);
console.log('Connected to MongoDB');

// ── Minimal schemas ───────────────────────────────────────────────────────────
const fileSchema  = new mongoose.Schema({}, { strict: false, collection: 'files' });
const groupSchema = new mongoose.Schema({}, { strict: false, collection: 'groups' });
const File  = mongoose.models.File  || mongoose.model('File',  fileSchema);
const Group = mongoose.models.Group || mongoose.model('Group', groupSchema);

// ── Helpers ───────────────────────────────────────────────────────────────────
function slugify(name) {
    return String(name || '')
        .toLowerCase()
        .replace(/\s+/g, '-')
        .replace(/[^a-z0-9-]/g, '')
        .replace(/-+/g, '-')
        .replace(/^-|-$/g, '') || 'group';
}

// ── Migration ─────────────────────────────────────────────────────────────────
const groups = await Group.find({ rootFolderPath: { $exists: true } }).lean();
console.log(`Found ${groups.length} group(s)`);

for (const group of groups) {
    const { _id, name, rootFolderPath, members } = group;
    if (!rootFolderPath) { console.log(`  ! No rootFolderPath for "${name}", skipping`); continue; }

    const slug    = slugify(name);
    const newPath = `/${slug}`;

    if (rootFolderPath === newPath) {
        console.log(`  ~ "${name}" already at ${newPath}`);
    } else {
        // Check for path collision
        const collision = await File.findOne({ filePath: newPath, type: 'directory' });
        let targetPath = newPath;
        if (collision) {
            targetPath = `/${slug}-${_id.toString().slice(-6)}`;
            console.log(`  ! Collision on ${newPath}, using ${targetPath} for "${name}"`);
        }

        const escapedOld = rootFolderPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

        // Cascade rename all files under oldRoot (filePath and parentPath)
        const { modifiedCount } = await File.updateMany(
            { filePath: { $regex: `^${escapedOld}(/|$)` } },
            [{ $set: {
                filePath:   { $replaceAll: { input: '$filePath',   find: rootFolderPath, replacement: targetPath } },
                parentPath: { $replaceAll: { input: '$parentPath', find: rootFolderPath, replacement: targetPath } }
            }}]
        );
        console.log(`  ✓ Renamed "${name}": ${rootFolderPath} → ${targetPath} (${modifiedCount} records)`);

        // Fix root folder metadata
        await File.updateOne(
            { filePath: targetPath, type: 'directory' },
            { $set: { parentPath: '/', fileName: name } }
        );

        // Update Group document
        await Group.updateOne({ _id }, { $set: { rootFolderPath: targetPath } });
    }

    // Backfill permissions.read / permissions.write from group members
    const readIds = [], writeIds = [];
    for (const m of (members || [])) {
        if (!m.user) continue;
        const uid = new mongoose.Types.ObjectId(m.user);
        if (m.role === 'WRITE' || m.role === 'OWNER') writeIds.push(uid);
        else readIds.push(uid);
    }
    const currentPath = rootFolderPath === newPath ? newPath : (await Group.findOne({ _id }).lean())?.rootFolderPath || newPath;
    if (readIds.length || writeIds.length) {
        const esc = currentPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const { modifiedCount: permCount } = await File.updateMany(
            { filePath: { $regex: `^${esc}(/|$)` } },
            { $addToSet: {
                ...(readIds.length  ? { 'permissions.read':  { $each: readIds  } } : {}),
                ...(writeIds.length ? { 'permissions.write': { $each: writeIds } } : {})
            }}
        );
        console.log(`  ✓ Backfilled permissions for "${name}" (${permCount} files)`);
    }
}

// Remove the /groups container node if it still exists
const del = await File.deleteOne({ filePath: '/groups', type: 'directory' });
if (del.deletedCount) console.log('  ✓ Removed /groups container node');

console.log('\nMigration complete.');
await mongoose.disconnect();

