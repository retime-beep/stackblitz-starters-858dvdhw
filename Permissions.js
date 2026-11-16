'use strict';

// Permission bits. Must match the PERMISSION BITS block in schema.sql.
const P = Object.freeze({
  ADMINISTRATOR: 1n << 0n,
  MANAGE_SERVER: 1n << 1n,
  MANAGE_ROLES: 1n << 2n,
  MANAGE_CHANNELS: 1n << 3n,
  KICK_MEMBERS: 1n << 4n,
  BAN_MEMBERS: 1n << 5n,
  TIMEOUT_MEMBERS: 1n << 6n,
  MANAGE_MESSAGES: 1n << 7n,
  VIEW_AUDIT_LOG: 1n << 8n,
  VIEW_CHANNEL: 1n << 9n,
  SEND_MESSAGES: 1n << 10n,
  READ_MESSAGE_HISTORY: 1n << 11n,
  ATTACH_FILES: 1n << 12n,
  ADD_REACTIONS: 1n << 13n,
  MENTION_EVERYONE: 1n << 14n,
  CREATE_INVITES: 1n << 15n,
  MANAGE_REPORTS: 1n << 16n,
  MANAGE_AUTOMOD: 1n << 17n,
  CONNECT: 1n << 18n, // voice, later
  SPEAK: 1n << 19n, // voice, later
});

const ALL = (1n << 20n) - 1n;
const TIMEOUT_ALLOWED = P.VIEW_CHANNEL | P.READ_MESSAGE_HISTORY;

// node-postgres returns bigint columns as strings, so always normalise to BigInt.
const big = (v) => BigInt(v ?? 0);

function has(perms, bit) {
  return (perms & bit) === bit;
}

/**
 * Server-wide permissions (no channel context). Use for things like ban/kick/manage roles.
 *
 * @param {object} args
 * @param {string} args.ownerId  servers.owner_id
 * @param {{userId: string, roleIds: string[]}} args.member  roleIds from member_roles
 * @param {Array<{id: string, is_everyone?: boolean, permissions: string|bigint}>} args.roles  all roles of the server
 * @returns {bigint}
 */
function computeBasePermissions({ ownerId, member, roles }) {
  if (member.userId === ownerId) return ALL;

  const memberRoleIds = new Set(member.roleIds);
  let perms = 0n;
  for (const role of roles) {
    if (role.is_everyone || memberRoleIds.has(role.id)) {
      perms |= big(role.permissions);
    }
  }
  if (has(perms, P.ADMINISTRATOR)) return ALL;
  return perms;
}

/**
 * Effective permissions of a member inside one channel.
 * Order: base -> @everyone overwrite -> role overwrites (combined) -> member overwrite -> timeout.
 *
 * @param {object} args
 * @param {string} args.ownerId
 * @param {{userId: string, roleIds: string[], timeoutUntil?: Date|string|null}} args.member
 * @param {Array} args.roles
 * @param {Array<{role_id?: string|null, user_id?: string|null, allow: string|bigint, deny: string|bigint}>} args.overwrites  rows of channel_overwrites for this channel
 * @param {Date} [args.now]
 * @returns {bigint}
 */
function computeChannelPermissions({
  ownerId,
  member,
  roles,
  overwrites = [],
  now = new Date(),
}) {
  const base = computeBasePermissions({ ownerId, member, roles });
  if (base === ALL) return ALL; // owner and administrators bypass overwrites and timeouts

  let perms = base;
  const memberRoleIds = new Set(member.roleIds);
  const everyone = roles.find((r) => r.is_everyone);

  // a) @everyone overwrite
  const everyoneOw = overwrites.find(
    (o) => o.role_id && everyone && o.role_id === everyone.id
  );
  if (everyoneOw) {
    perms = (perms & ~big(everyoneOw.deny)) | big(everyoneOw.allow);
  }

  // b) all of the member's role overwrites, combined
  let roleAllow = 0n;
  let roleDeny = 0n;
  for (const o of overwrites) {
    if (o.role_id && memberRoleIds.has(o.role_id)) {
      roleAllow |= big(o.allow);
      roleDeny |= big(o.deny);
    }
  }
  perms = (perms & ~roleDeny) | roleAllow;

  // c) the member's own overwrite
  const memberOw = overwrites.find(
    (o) => o.user_id && o.user_id === member.userId
  );
  if (memberOw) {
    perms = (perms & ~big(memberOw.deny)) | big(memberOw.allow);
  }

  // Timeout: strip everything except viewing and reading history.
  if (member.timeoutUntil && new Date(member.timeoutUntil) > now) {
    perms &= TIMEOUT_ALLOWED;
  }

  // Can't see the channel -> can't do anything in it.
  if (!has(perms, P.VIEW_CHANNEL)) return 0n;

  return perms;
}

/** Position of the member's highest role (@everyone counts as 0). */
function topRolePosition(member, roles) {
  const ids = new Set(member.roleIds);
  let top = 0;
  for (const r of roles) {
    if (ids.has(r.id) && r.position > top) top = r.position;
  }
  return top;
}

/**
 * Hierarchy check for kick/ban/timeout/role changes.
 * This only checks rank. The caller must ALSO check the permission bit, e.g.
 * has(computeBasePermissions(...), P.BAN_MEMBERS).
 */
function canManageMember({ ownerId, actor, target, roles }) {
  if (target.userId === ownerId) return false; // the owner can't be targeted
  if (actor.userId === ownerId) return true; // the owner can target anyone else
  return topRolePosition(actor, roles) > topRolePosition(target, roles);
}

module.exports = {
  P,
  ALL,
  has,
  computeBasePermissions,
  computeChannelPermissions,
  topRolePosition,
  canManageMember,
};
