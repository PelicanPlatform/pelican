# Pelican User / Group Management Design

# Goal

This document describes the “user” and “group” entities within the Pelican server, their attributes, and how they can be used.

# Users

The user object represents an entity (typically a human but a service / robot account could be a user) that can invoke Pelican server APIs.

The user’s record has the following properties:

- **ID**: Unique primary key for the record. Auto-generated, human-unreadable (“fca7e48c”), immutable. Must NOT be used for authorization; should NOT be presented to the web interface (it’s OK if it’s embedded in URLs, just avoid user-facing displays).
- **Name**: The unique machine-readable name (“bockelman”). May be used for authorization decisions or in policy written by humans (e.g., referred to in the configuration file under the list of administrators; web displays should manipulate based on ID instead). Editable only by administrators. It may be auto-created based on the first sign-in from the
- **Display Name**: The human-readable name (“Brian Bockelman”). Used to display information to humans in the web interface. Decisions that impact authorization (e.g., add/remove from a group, transfer ownership) MUST show both display name and name in the UI. Can be self-edited by the user.
- **Identities**: A user has one or more *identity*; the identity is used solely for authentication (not authorization). Identities have an issuer and subject (terminology mirroring the fact these are created via OIDC typically).
  - The “internal issuer” (the issuer URL used by the server for creating authorizations like cookies, not for data access) identity is set when the user has a locally-stored password. In this case, the sub must match the user’s name.
  - To prevent humans from sharing an account, each user may have at most one associated sub per issuer.
  - A (sub, issuer) tuple may not be associated with more than one user.
  - Users may not edit their identities but are permitted to unlink one.
- **Creation date, last edit date**: Metadata about changes; useful in diagnosing the source of users.
- **Creator**: The user ID + session info that created this record. A special value, “self-enrolled” indicates the user was created on login. The special value “unknown” indicates the user record predated this field. The session info should indicate whether the creator was from the web interface or an API key (and what API key)
- **Scopes**: A list of known permissions the user has in the Pelican server. These may be implicit (not stored in the DB; current example: UI access). Scopes are not editable by users.

**Notes**:

- User names should pass a reasonable regular expression. Particularly, `/` should be a banned character as group names are often used in object name authorization.
- Users are solely used for *authentication*. Existence of a user record does not imply specific authorizations.
- Admins may create invite links, a randomly-generated capability (used in a link) that is used in password creation workflows for the internal issuer.
- Users should NOT be able to create passwords on their own; that would allow them to persist after OIDC-based access goes away. Administrators (or users with the appropriate permissions) should be able to invite users to create passwords or remove user’s ability to use passwords.

# Groups

A group is a set of users; membership in a group is used to determine additional authorizations a user may receive.

A group has the following properties:

- **ID**: Unique primary key for the record. Auto-generated, human-unreadable (“fca7e48c”), immutable. Should NOT be presented to the web interface.
- **Name**: The unique machine-readable name (“brians-friends”). May be used in policy written by humans (e.g., referred to in the configuration file under the list of administrator groups; web displays should manipulate based on ID instead). Editable only by administrators.
- **Display name**: The human-readable name (“Brian’s Friends”). Used to display information to humans in the web interface. Decisions that impact authorization MUST show both display name and name in the UI. Can be self-edited by the group owners.
- **Membership**: A set of user IDs that are in the group.
- **Owner**: A user ID that owns the group.
- **Administrator**: A user ID or group ID that can manipulate group membership and display name.
- **Auth-template eligibility**: A boolean flag controlling whether this group's name is allowed to match `Issuer.AuthorizationTemplates` and the `Server.*AdminGroups` config lists. Settable only by an administrator or user-administrator (see "Group creation" note below). Pre-existing groups, minted before group creation was open to all users, are eligible by default.
- **Source**: Which provider the record came from — `pelican` (created through the group-management API; `group_members` is the authoritative membership list), or the name of the provider that asserts it (`oidc`, `file`, `github`, matching the `Issuer.GroupSource` vocabulary). See "Group sources" below.
- **Creation date, last edit date**: Metadata about changes; useful in diagnosing the source of users.
- **Creator**: The user ID + session info that created this record. Similar to creator for users.
- **Scopes**: A list of known authorizations the group has in the Pelican server.
- **Deletion**: A soft delete, like users. The ID is spent permanently; the name is released. See "Identifiers in the database".

**Notes**:

- Group names should pass a reasonable regular expression. Particularly, `/` should be a banned character as group names are often used in object name authorization.
- **Group creation is open to any authenticated user.** This is necessary so users can mint groups for their own collection ACLs and for shares. The privilege gradient sits on the *auth-template-eligibility* bit, not on the act of creation: a non-admin can create a group, become its owner, and use it in any *operator-set* surface (collection ACLs, share ACLs) — but the group will *not* match `Issuer.AuthorizationTemplates` or `Server.*AdminGroups` until an admin or user-admin flips it eligible. The reasoning is that templates and admin-group config use group *names* as bearer authority (e.g. `Prefix: /projects/$GROUP` or `Server.AdminGroups: [sysadmins]`), so a self-named group must not auto-promote into those surfaces.
- Users are permitted to *leave* a group. Hence, there should be no negative authorizations based on group membership (e.g., “banned user group”-style of authorizations).

## Group sources

A group record names the provider it came from, using the same vocabulary as the `Issuer.GroupSource` configuration value. There is deliberately no "internal vs external" split: Pelican reads membership from several providers, they behave differently from each other, and an operator debugging "why is this user in this group" needs to know which one to go look at.

| Source    | Membership decided by               | Notes                                                                                                                                   |
| --------- | ----------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `pelican` | `group_members` in this database    | The only source a user can create a group in.                                                                                           |
| `oidc`    | the identity provider's group claim |                                                                                                                                         |
| `file`    | `Issuer.GroupFile`                  |                                                                                                                                         |
| `github`  | GitHub organization membership      |                                                                                                                                         |
| `unknown` | some provider, unrecorded           | Backfilled by migration from a collection ACL that named a group Pelican had no record of. The next assertion stamps the real provider. |

Every source but `pelican` is *asserted*: the named provider, not this server, decides who is in the group.

Group names used to arrive from two unreconciled places — records in this table, and whatever a provider asserted in a token. Because ACLs matched on the name, the two were indistinguishable at authorization time, which was a problem in both directions: an authorization handle that only existed inside a token had no record for a grant to point at, and an unprivileged user could create a group named after one the provider asserts and step into whatever that name was granted.

Pelican therefore records a group the first time it observes an asserted name. The record is owned by the built-in `admin` user, is stamped with the asserting provider, and is auth-template eligible — which preserves rather than changes existing behavior, since a name with no record already matched templates. Its membership is **not** written to `group_members`: the asserting provider remains the source of truth for who belongs, and a caller's asserted names are resolved to these IDs on each request. Because the name is now taken, `CreateGroup` refuses it.

An asserted group cannot be renamed — its name is the link to the provider's assertion — but an administrator may edit its display name and description, grant it scopes, use it as a collection ACL target or admin group, and add local members to it alongside the asserted ones. If a name is already held by a `pelican` group when a provider first asserts it, the `pelican` group wins and the collision is logged; it is never promoted to auth-template eligibility by an assertion.

Operators who do not want Pelican writing groups it did not create can set `Issuer.DisableGroupAutoCreation`. The cost is that an asserted group has no ID, so it cannot be named in a collection ACL, and its name stays available for any authenticated user to claim.

## Mirrored memberships

Recording the group is not enough on its own. Membership still lives at the provider, which works for the caller in front of us — their asserted names are resolved to group IDs on each request — and fails for every decision made *about* a user who is not in front of us: whether the owner of a share still has access to its parent collection (computed at token-mint time, with no session for that owner), whether an account a user-administrator is about to act on is itself a system administrator, or simply who is in this group.

So Pelican also mirrors the memberships, into `group_members` alongside the ones administrators create. A row's `source` says which it is: `pelican` for a membership created through the group API — authoritative, never expires, and an assertion never overwrites or retracts one — or the provider that asserted it, with `asserted_at` recording when it last did so.

A mirrored membership is a **cached authorization fact**, and a cache that outlives the fact is the same bug as a name that outlives its principal. One rule keeps it honest:

> **Freshness gates granting, not existence.**

A mirrored row may hand out access only while the provider has asserted it within `Issuer.AssertedGroupMembershipTTL`. Past that it is *kept*, not deleted — because a check that asks whether an account might *hold* a privilege has to keep seeing it. For `IsSystemAdminUserID`, "we last saw this account in an admin group a month ago" must mean *refuse*; treating a stale copy as absence is exactly what opens that guard. Consumers therefore declare which direction is safe for them: granting paths filter on freshness, restricting paths do not. Rows go away only when the provider stops asserting them.

The caller's own live assertion is never gated by the TTL — that is the provider speaking directly, not a cache.

Only `file` can be refreshed without the user present, since it is a local file keyed by username; `Issuer.GroupFileRefreshInterval` re-reads it and reconciles every known account, so removing someone from the file takes effect within one interval rather than at their next login. `oidc` and `github` need that user's own token and so refresh at login, which is what the TTL exists to bound.

A mirrored membership cannot be removed through Pelican — not by the member, not by an administrator. The provider still asserts it, so the row would reappear at the next login; the removal has to happen at the provider. Adding a *local* member to an asserted group is fine, and that membership is Pelican's: it does not expire and an assertion will not retract it.

# Identifiers in the database

Every stored reference used for an authorization decision is an **ID**, never a name. Concretely:

- `collections.owner_id` is the sole ownership handle. There is no companion username column; the `owner` field in API responses is resolved from the `users` table for display.
- `collection_acls` rows are keyed on `(subject_type, subject_id)`, where `subject_id` is a Group.ID, a User.ID, or empty for the all-authenticated sentinel. The `user-<username>` and `@authenticated` spellings are *presentation* forms accepted and returned by the API; they never reach a column.
- Audit columns (`granted_by`, `added_by`, `created_by`) hold User.IDs or the `unknown` / `self-enrolled` sentinels.
- `api_keys.created_by` holds the creator's User.ID. It is not an audit field: a key's persisted scopes are re-intersected against that user's *current* effective scopes on every call, so the column decides what the key can do. A username there meant a rename silently bricked the key and a reused username revived it for whoever still held the secret.

The two spaces are kept **disjoint**: `ValidateIdentifier` refuses any name of the shape an ID takes (eight lowercase hex characters). Without that, anywhere a handle may be either — an ACL grant target, say — a user could create a group whose *name* is another principal's *ID* and intercept every reference addressed to it, which is the same confusion one layer up. Disjointness also means a resolver can tell which space a handle belongs to by looking at it, instead of trying one and falling back to the other.

A bare user ID is deliberately not accepted as an ACL target: `user-<username>` names a user in the name space and the API's `subjectType` + `subjectId` pair names one in the ID space, so a third, guessed spelling would buy nothing.

This is what makes renaming safe. A rename changes one row in `users` or `groups`; nothing else references the old value, so there is nothing to migrate and nothing left behind for a later claimant of that name. It is also why granting an ACL to a name this server has no record of is an error rather than a stored string: a stored name would be matched by whoever holds it next.

**IDs are never reused.** Deleting a user is a soft delete: the row stays, so the ID is spent permanently and historical references remain resolvable, while the account confers nothing. Deleting a group works the same way and for the same reason — a Group.ID is an authorization handle, and `generateSlug` picks eight hex characters with no uniqueness check, so freeing one would let a later group be minted with it and inherit whatever still pointed there. `DeleteGroup` additionally clears every such reference (ACL grants, group scopes, memberships, invite links, and any collection or group that named it as administrator), so the cleanup is exhaustive *and* the ID cannot come back.

**Names are reused, deliberately.** A soft-deleted user releases its username and its `(sub, issuer)` identity so the person can re-enrol; a soft-deleted group releases its name so an operator can recreate it after a cleanup. That is safe precisely because nothing stores a name as an authorization handle — the next holder inherits nothing.

# Authorizations

- For most web UI actions, authorization to perform an action should be based on the calculated scopes from the user and associated group records.
- Deleted users have no authorizations.
- API keys are intended for the long-lived credential use case (no renewal but revocation), not as the primary access path. For accessing objects and collections, users should rely on OAuth2-issued tokens from a normal web login, which already carry their permitted scopes.
  - API key creation is admin-only: the web UI’s API-key endpoints require the server-admin privilege.
  - Actions from API keys must be distinguishable (for creators / deleters, etc) from those done by the web UI. At least the key ID must be recorded if a key was used.
  - Users can lose authorizations after the API key was used. Thus, when an API key is used, its scopes must be intersected with the current scopes for the user.
