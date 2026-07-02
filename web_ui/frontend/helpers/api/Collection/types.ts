// Collection types mirror the backend's /api/v1.0/origin_ui/collections
// surface — ListCollectionRes for list/get and CollectionACL for the
// per-collection ACL endpoint. Kept narrow on purpose; the admin pages
// don't need the full Collection record (members/metadata) yet.

export type CollectionVisibility = 'private' | 'public';

// UserCard / GroupCard mirror the database.UserCard / database.GroupCard
// shapes — minimum needed to render "Display Name (username)" or a
// group label without pulling the full record. Re-declared here so the
// Collection module is self-contained.
export interface CollectionUserCard {
  id: string;
  username: string;
  displayName: string;
}
export interface CollectionGroupCard {
  id: string;
  name: string;
}

export interface CollectionSummary {
  id: string;
  name: string;
  description: string;
  namespace: string;
  visibility: CollectionVisibility;
  // owner is the legacy username field (kept for back-compat / audit).
  // ownerId is the User.ID slug — the authoritative ownership handle
  // going forward. adminId is the admin group's slug (empty when no
  // admin group is configured).
  owner: string;
  ownerId?: string;
  adminId?: string;
  // Server-resolved {id, username, displayName} / {id, name} cards.
  // Populated by the list endpoint in one batched query so the listing
  // page can render "Display Name (username)" / admin-group labels
  // without an N+1 round-trip. Either may be omitted when the
  // referenced row is missing (deleted user, no admin group).
  ownerCard?: CollectionUserCard;
  adminCard?: CollectionGroupCard;
  // Server-computed: true when the calling user can PATCH this row
  // (owner, admin-group member, or server.collection_admin / admin
  // holder). Lets the listing UI hide edit affordances on rows where
  // a save would 403, without the frontend having to re-implement
  // the membership check. Always present from the backend.
  canEdit?: boolean;
  // enableSharing is the operator-set opt-in that lets read-access
  // holders mint a "share" — a child collection that delegates a
  // subset of this one's access. Defaults false on the backend.
  enableSharing?: boolean;
  // parentCollectionId, when non-empty, marks this row as a SHARE of
  // the named collection. The backend omits this field on regular
  // (non-share) rows; in TypeScript we treat empty / missing as
  // equivalent.
  parentCollectionId?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface CollectionPost {
  name: string;
  namespace: string;
  description?: string;
  visibility: CollectionVisibility;
  metadata?: Record<string, string>;
}

// Mirrors database.AclRole. Role strings are the wire values accepted
// by POST /collections/:id/acl.
export type CollectionAclRole = 'read' | 'write' | 'owner';

export interface CollectionAcl {
  collectionId: string;
  // Group identifier used in ACL grants. Stored as the group *name*
  // (not slug) — see GrantCollectionAcl in database/collection.go,
  // which canonicalises slug->name before persisting. Matching with
  // the /groups list keys off the `name` field for that reason.
  groupId: string;
  role: CollectionAclRole;
  createdBy?: string;
  createdAt?: string;
  expiresAt?: string | null;
}

export interface CollectionAclGrant {
  groupId: string;
  role: CollectionAclRole;
  expiresAt?: string;
}

// ALL_AUTHENTICATED_USERS_ACL_GROUP is the sentinel value stored in
// `CollectionAcl.groupId` to grant access to every authenticated
// caller. The backend constant is `database.AllAuthenticatedUsersACLGroup`
// and the wire format must stay in sync with it. Begins with `@`,
// which group-name validation rejects, so this can't collide with a
// real group name.
export const ALL_AUTHENTICATED_USERS_ACL_GROUP = '@authenticated';

// labelForACLTarget renders an ACL row's `groupId` for human display.
// For the all-authenticated-users sentinel it returns the friendly
// label; everything else (real group names) returns unchanged.
export const labelForACLTarget = (groupId: string): string =>
  groupId === ALL_AUTHENTICATED_USERS_ACL_GROUP
    ? 'All authenticated users'
    : groupId;
