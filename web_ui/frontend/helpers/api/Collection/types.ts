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

// What kind of principal an ACL row grants its role to. The server
// stores the row as (subjectType, subjectId) where subjectId is an
// immutable Group.ID or User.ID — never a name — so renaming or
// deleting a principal can't leave a grant behind for whoever claims
// the name next.
export type CollectionAclSubjectType = 'group' | 'user' | 'authenticated';

export interface CollectionAcl {
  collectionId: string;
  subjectType: CollectionAclSubjectType;
  // The stored ID: a Group.ID, a User.ID, or empty for 'authenticated'.
  subjectId: string;
  // Current display handle for subjectId — a group name, a username, or
  // the '@authenticated' sentinel. Server-resolved; empty when the
  // subject row has been deleted.
  subjectName: string;
  // Legacy spelling of the target, kept so older clients keep working:
  // the group name, `user-<username>`, or '@authenticated'. Derived
  // from subjectName — matching against the /groups list still keys off
  // the `name` field. Prefer subjectId when writing new code.
  groupId: string;
  role: CollectionAclRole;
  createdBy?: string;
  createdAt?: string;
  expiresAt?: string | null;
}

export interface CollectionAclGrant {
  // A NAME, despite the field name: a group name, `user-<username>`,
  // or the '@authenticated' sentinel. The server resolves it to a
  // stored (subjectType, subjectId) pair and rejects anything that
  // matches nothing. An ID of either kind is NOT a spelling here —
  // pass subjectType/subjectId to address a principal by ID.
  groupId: string;
  role: CollectionAclRole;
  expiresAt?: string;
}

// Address a principal by its stored ID instead of resolving a name.
// The only way to grant to a user by ID.
export interface CollectionAclGrantBySubject {
  subjectType: CollectionAclSubjectType;
  subjectId: string;
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

// labelForACLTarget renders an ACL row's target for human display.
// Accepts either a whole row (preferred — it carries the subject type)
// or the bare legacy `groupId` string.
//
// A row whose subject has been deleted has an empty subjectName; we say
// so explicitly rather than rendering a blank chip, since such a row
// matches nobody and is there to be revoked.
export const labelForACLTarget = (target: CollectionAcl | string): string => {
  if (typeof target === 'string') {
    return target === ALL_AUTHENTICATED_USERS_ACL_GROUP
      ? 'All authenticated users'
      : target;
  }
  switch (target.subjectType) {
    case 'authenticated':
      return 'All authenticated users';
    case 'user':
      return target.subjectName
        ? `${target.subjectName} (user)`
        : '(deleted user)';
    default:
      return target.subjectName || '(deleted group)';
  }
};
