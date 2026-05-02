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
