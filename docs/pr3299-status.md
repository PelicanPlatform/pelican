# PR #3299 vs Issue #3298 — Status Report

Reviewed and updated 2026-04-02.

## Issue Requirement 1: Group Owner/Admin Model

**Status: Done**

- DB migration adds `owner_id`, `admin_id`, `admin_type` to `groups` table, with backfill of `owner_id` from `created_by`.
- `isGroupOwnerOrAdmin` / `isGroupOwnerOnly` helpers replace all legacy `CreatedBy`-only checks in `UpdateGroup`, `AddGroupMember`, `RemoveGroupMember`, `DeleteGroup`.
- Admin can be a user or another group (membership checked via `GroupMember` table).
- `PUT /groups/{id}/ownership` endpoint for changing owner/admin.

## Issue Requirement 2: Group Invite Links

**Status: Done**

- Invite tokens stored as bcrypt hashes; plaintext returned only once at creation.
- `POST /groups/{id}/invites`, `GET /groups/{id}/invites`, `DELETE /groups/{id}/invites/{linkId}`, `POST /invites/redeem` endpoints.
- Configurable expiry via `Server.GroupInviteLinkExpiration` (duration type, default `168h`), single-use option.
- User-onboarding invite links (`POST /invites/onboarding`) for onboarding without group addition.
- **Auto-create user on redeem**: `RedeemGroupInviteLink` now accepts sub/issuer/username and auto-creates a user if one doesn't exist, or finds existing user by identity.
- **Configurable username claim list**: `Server.AutoEnrollUsernameClaims` parameter (stringSlice, default `["preferred_username", "email", "sub"]`) configures which claims to derive username from.
- **Identity resolution on redeem**: Handler extracts `OIDCSub`/`OIDCIss` from JWT context and passes to redeem function for identity-based user lookup or creation.

## Issue Requirement 3: User Status Tracking

**Status: Done**

- `status` (active/inactive), `last_login_at`, `display_name` columns added to users.
- `UpdateUserLastLogin` called in `setLoginCookie`.
- `PUT /users/{id}/status` endpoint for setting status and display name.

## Issue Requirement 4: AUP Tracking

**Status: Done**

- `aup_version`, `aup_agreed_at` columns added to users.
- `POST /users/{id}/aup` endpoint to record AUP version agreement.
- `Server.AUPFile` parameter defined (path to Markdown AUP file).
- **AUP content endpoint**: `GET /api/v1.0/auth/aup` serves the AUP file contents with a SHA256-based version hash.
- **AUP enforcement**: `whoamiHandler` now computes AUP version and compares with user's recorded version; returns `requiresAUP` and `aupVersion` in response so the UI can gate access.

## Issue Requirement 5: User/Collection Administrator Permissions

**Status: Done**

- `CheckUserAdmin()` and `CheckCollectionAdmin()` helper functions defined.
- Config params: `Server.UserAdminUsers`, `Server.UserAdminGroups`, `Server.CollectionAdminUsers`, `Server.CollectionAdminGroups`.
- System admins inherit both roles.
- **`CheckCollectionAdmin` wired into all 6 collection handlers** in `origin/collections.go` (replaces `CheckAdmin`).
- **User admin guards enforced**: `handleUpdateUserStatus` checks `CheckUserAdmin`, validates status values (`active`/`inactive` only), and blocks user admins from modifying system admin targets via `IsSystemAdminUserID`.
- **`handleDeleteUser`** allows both system admins and user admins, with protection against user admins deleting system admin accounts.
- **Input validation**: `UserStatus` values validated to prevent arbitrary strings in the status column.

## Issue Requirement 6: Multiple Identities Per User

**Status: Done**

- `user_identities` table with FK to users, unique index on `(sub, issuer)`.
- `GET/POST /users/{id}/identities`, `DELETE /users/{id}/identities/{identityId}` endpoints.
- `GetUserByIdentity` checks both primary user table and `user_identities` table.

## Cross-Cutting: CLI Equivalents

**Status: Done**

- `pelican origin group` — list, create, delete, add-member, remove-member, set-ownership, invite (create/list/revoke/redeem).
- `pelican origin user` — list, create, delete, set-status, identity (list/add/remove).
- Uses `fetchOrGenerateWebAPIAdminToken` pattern.

## Cross-Cutting: Web UI

**Status: Done**

- Collection listing page at `/origin/collections` with search and delete — now accessible to both `admin` and `user` roles.
- Collection creation page at `/origin/collections/create` with group ACL assignment — now accessible to `admin` and `user` roles.
- **Inline group creation**: "Create New Group" dialog in collection creation page allows creating groups without leaving the flow.
- **Invite link generation in collection flow**: After creating a collection with an owner group, an invite link is automatically generated and shown in a dialog for copying.
- **Group management UI**: New `/origin/groups` page allows authenticated users to create groups, delete groups, and manage invite links (generate, view, revoke).
- Navigation updated: "Collections" and "Groups" links added to the origin sidebar.
- TypeScript types updated for all new models.

## Cross-Cutting: Backward Compatibility

**Status: Done**

- All new DB columns have defaults; new tables only.
- Migration backfills `owner_id` from `created_by`.
- Down migration drops new tables (SQLite limitation prevents dropping columns).

## Cross-Cutting: Tests

**Status: Done**

- `TestRedeemGroupInviteLink`: 8 sub-tests covering existing user redemption, auto-creation, username derivation from sub, expired links, single-use links, invalid tokens, missing identity, and identity-based user lookup.
- `TestInputValidation_UserStatus`: 3 sub-tests verifying valid/invalid status values.

## Cross-Cutting: Security

**Status: Done**

- Invite tokens stored as bcrypt hashes.
- All new routes require `AuthHandler` + `WebUi_Access` scope.
- Admin-only endpoints check appropriate admin status.
- Input validation on `UserStatus` values prevents arbitrary strings.
- System admin accounts protected from modification by user admins.

## Summary Table

| # | Requirement | Status |
|---|---|---|
| 1 | Group owner/admin model | **Done** |
| 2 | Group invite links (auto-create, claim config) | **Done** |
| 3 | User status tracking | **Done** |
| 4 | AUP tracking and enforcement | **Done** |
| 5 | User/collection admin permissions | **Done** |
| 6 | Multiple identities per user | **Done** |
| — | CLI commands | **Done** |
| — | Web UI (collection + group mgmt pages) | **Done** |
| — | Tests | **Done** |
| — | Backward compatibility | **Done** |
