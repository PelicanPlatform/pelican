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
- **Creation date, last edit date**: Metadata about changes; useful in diagnosing the source of users.
- **Creator**: The user ID + session info that created this record. Similar to creator for users.
- **Scopes**: A list of known authorizations the group has in the Pelican server.

**Notes**:

- Group names should pass a reasonable regular expression. Particularly, `/` should be a banned character as group names are often used in object name authorization.
- Group creation either should require a specific scope or be limited to administrators.
- Users are permitted to *leave* a group. Hence, there should be no negative authorizations based on group membership (e.g., “banned user group”-style of authorizations).

# Authorizations

- For most web UI actions, authorization to perform an action should be based on the calculated scopes from the user and associated group records.
- Deleted users have no authorizations.
- Users may generate an API key with a subset of their authorizations.
  - Actions from API keys must be distinguishable (for creators / deleters, etc) from those done by the web UI. At least the key ID must be recorded if a key was used.
  - Users can lose authorizations after the API key was used. Thus, when an API key is used, its scopes must be intersected with the current scopes for the user.
