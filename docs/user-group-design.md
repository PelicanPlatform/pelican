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

A group record names the provider it came from, using the same terminology as the `Issuer.GroupSource`.

| Source    | Membership decided by               | Notes                                                                                                                                                                                      |
| --------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `pelican` | `group_members` in this database    | The only source a user can create a group in.                                                                                                                                              |
| `oidc`    | the identity provider's group claim | Typically taken from the OIDC user_info endpoint or the contents of the authentication token.                                                                                              |
| `file`    | `Issuer.GroupFile`                  |                                                                                                                                                                                            |
| `github`  | GitHub organization membership      |                                                                                                                                                                                            |
| `unknown` | some provider, unrecorded           | Reserved at startup from `Server.*AdminGroups`, or backfilled by migration from a collection ACL that named a group Pelican had no record of. The next assertion stamps the real provider. |

Every source but `pelican` is *asserted* by an external entity: the named provider, not this server, decides who is in the group.

Pelican records a group the first time it observes an asserted name. The record is owned by the built-in `admin` user, is stamped with the asserting provider, and is auth-template eligible. The asserting provider remains the source of truth for who belongs, and a caller's asserted names are resolved to these IDs on each request. Because the name is now taken, users cannot create a second group.

An asserted group cannot be renamed — its name is the link to the provider's assertion — but an administrator may edit its display name and description, grant it scopes, use it as a collection ACL target or admin group, and add local members to it alongside the asserted ones. If a name is already held by a `pelican` group when a provider first asserts it, the `pelican` group wins and the collision is logged; it is never promoted by an assertion.

Operators who do not want Pelican writing groups it did not create can set `Issuer.DisableGroupAutoCreation`. The cost is that an asserted group cannot be named in a collection ACL, and its name stays available for any authenticated user to claim.

## Reserved administrator group names

A group name listed in `Server.AdminGroups`, `Server.UserAdminGroups` or `Server.CollectionAdminGroups` confers a scope on whoever holds it, so the server takes those names at startup if they're available.

Without that, an unprivileged user could take one. Group creation is open (but unprivileged-created groups cannot confer admin) so a user-created group called `ops` removes `ops` from *every* caller's group list, revoking `server.admin` from every administrator who held it through the provider's assertion. If it was created at startup, the group is stamped with the `unknown` source.

A configured name the server cannot record — one carrying the `user-` personal prefix, a leading `@`, or over the length limit — fails startup rather than being skipped. A reserved group cannot be deleted while the configuration still names it: deletion releases the name, which would let a user claim it before the next startup reserved it again. Removing the configuration entry makes the group ordinary.

The admin group reservation happens regardless of `Issuer.DisableGroupAutoCreation` setting.

## Mirrored memberships

Authoritative membership information lives at the provider but is mirrored in the database for when authorization decisions need to be made based on a user other than the one making the requestion. For example, whether the owner of a share still has access to its parent collection (computed at token-mint time, with no session for that owner) or whether an account a user-administrator is about to act on is itself a system administrator.

Membership can be mixed, but only in one direction. An asserted group holds mirrored rows *and* any local members an administrator added alongside them; a `pelican` group's *member list* holds only local ones, because the reconciliation step refuses to accept a name a `pelican` group already holds and the mirror filters those groups out of its lookup.

That refusal covers membership, not authorization: a caller's asserted name still resolves to a `pelican` group's ID on each request, and so confers that group's ACL grants and scopes. The two questions are different. Membership is a list this server keeps, and a provider does not get to edit it. Authorization asks who the caller is, and the provider is what tells us — including the username. A provider that wanted a group's access could simply assert one of its members' identities, so refusing the name would buy nothing; the trust in the provider is assumed, not something the group model can withdraw.

It is also what makes a useful arrangement work: create a group through the groups API, point a collection's `admin_id` at it, and let the provider decide who is in it. Pelican still logs the collision when a provider asserts a name a `pelican` group holds, because it means the group's member list and its effective membership have diverged, which is worth knowing even when it is intended. An operator who wants to add a collaborator that the identity provider does not carry can do so; an identity provider cannot quietly add anyone to a group this server owns.

That asymmetry is why the source is recorded in two places, on the group and again on each membership. The group's source says **who decides its membership by default**; the row's source says **how that particular row got there, and whether it may expire**. Collapsing them would leave the retraction pass unable to distinguish an administrator's decision from a provider's. Since retraction runs on every login, it would delete the administrator's on the member's next sign-in.

A mirrored membership is a **cached authorization fact**. One important rule of thumb:

> **Freshness gates granting, not existence.**

A mirrored row may hand out access only while the provider has asserted it within `Issuer.AssertedGroupMembershipTTL`. Past that it is *kept*, not deleted because a check that asks whether an account might *hold* a privilege has to keep seeing it. For example, "we last saw this account in an admin group a month ago" must mean *refuse*. Internal API consumers declare which direction is safe for them: granting paths filter on freshness, restricting paths do not. Rows go away when the provider doesn't assert them on next login.

The caller's own live assertion (from the request token) is never gated by the TTL.

Currently, only `file` can be refreshed without the user present since it is a local file keyed by username. `Issuer.GroupFileRefreshInterval` re-reads it and reconciles every known account, so removing someone from the file takes effect relatively quickly. `oidc` and `github` need that user's own token and so refresh at login.

## Establishing that an account is *not* an administrator

`Server.AdminGroups` confers the `server.admin` privilege by group membership, so when membership comes from a provider, we may have to work from the cache. Any code that asks "is this account an administrator?" must be conservative about allowing access. For example, a caller holding only `server.user_admin` could rename, delete, or mint a password-set invite for an administrator's account if this was calculated incorrectly.

So the question is not "have we proved this account **is** an administrator" but "have we proved it is **not** an admin". `users.group_admin_status` latches the answer based on the user settings:

| state       | meaning                                                                              | a user-administrator may act? |
| ----------- | ------------------------------------------------------------------------------------ | ----------------------------- |
| `unknown`   | never established — the default, and what every account carries until first observed | no                            |
| `possible`  | observed holding a group that confers admin. Persisted over time.                    | no                            |
| `ruled-out` | groups observed, none administrative                                                 | yes                           |

A provider retracting an administrative membership removes the evidence, not the history, and an account that could once administer this server should not become manageable because a group assignment changed.

`unknown` is conservative by design: on upgrade to the new user/group scheme, every account is in this state so a user-administrator can act on none until each has signed in once. Where `Server.AdminGroups` is unset no group can confer admin and hence accounts are set to `ruled-out`. The same is true where membership is Pelican's own, since `group_members` is then complete and there is nothing additional a provider could assert.

Under `oidc` or `github`, though, only that account signing in clears `unknown` — so an account that never signs in again would stay untouchable forever. A user with the `server.admin` scope may record the judgement directly`. It moves an account from `unknown`to`ruled-out`. It is not permanent — a later observation still latches `possible\`. It grants the caller nothing they did not already have, since a full administrator anyway.

The two predicates in the code are `MustTreatAsSystemAdmin` (restricting — uncertainty refuses) and `IsConfirmedSystemAdmin` (granting — uncertainty declines).

## Removing a mirrored membership

A mirrored membership cannot be removed through Pelican's REST APIs. The provider still asserts it, so the row would reappear at the next login; the removal has to happen at the provider. Adding a *local* member to an asserted group is fine: it does not expire and an assertion will not retract it.

# Identifiers in the database

Every stored reference used for an authorization decision is an immutable **ID** not a user/group name. Concretely:

- `collections.owner_id` is the sole ownership handle; previously, there was a confounding username column as well.
- `collection_acls` rows are keyed on `(subject_type, subject_id)`, where `subject_id` is a Group.ID, a User.ID, or empty for the all-authenticated sentinel. The `user-<username>` and `@authenticated` spellings are *presentation* forms accepted and returned by the API.
- Audit columns (`granted_by`, `added_by`, `created_by`) hold User.IDs or the `unknown` / `self-enrolled` sentinels (particularly for pre-existing rows).
- `api_keys.created_by` holds the creator's User.ID. A key's persisted scopes are re-intersected against that user's *current* effective scopes on every call, so the column can only further limit permissions.

Using IDs is what makes renaming safe. A rename changes one row in `users` or `groups`; nothing else references the old (username / groupname) value, so there is nothing to migrate and nothing left behind for a later claimant of that name.

**IDs are never reused.** Deleting a user or group is a soft delete: the row stays, so the ID is spent permanently and historical references remain resolvable. Doing a hard delete without cleaning up the historical references would let a later group be minted with the same ID and inherit whatever still pointed there. `DeleteGroup` clears every reference (ACL grants, group scopes, memberships, invite links, and any collection or group that named it as administrator), but not any audit rows.

**Names are reused, deliberately.** A soft-deleted user releases its username and its `(sub, issuer)` identity so the person can re-enroll; a soft-deleted group releases its name so an operator can recreate it after a cleanup. That is safe precisely because nothing stores a name as an authorization handle.

# Authorizations

- For most web UI actions, authorization to perform an action should be based on the calculated scopes from the user and associated group records.
- Deleted users have no authorizations.
- API keys are intended for the long-lived credential use case (no renewal but revocation), not as the primary access path. For accessing objects and collections, users should rely on OAuth2-issued tokens from a normal web login, which already carry their permitted scopes.
  - API key creation is admin-only: the web UI’s API-key endpoints require the server-admin privilege.
  - Actions from API keys must be distinguishable (for creators / deleters, etc) from those done by the web UI. At least the key ID must be recorded if a key was used.
  - Users can lose authorizations after the API key was used. Thus, when an API key is used, its scopes must be intersected with the current scopes for the user.
