# Pelican Collection Design

# Goal

This document describes the “collection” and “shares” concepts within the Pelican server and how they are meant to be used.

# Collections

A collection is a prefix within an exported namespace and associated ACLs. This allows an origin administrator to provide more complicated access control within the namespaces beyond the template matching facilities (e.g., providing write access to /foo/$USER).

The collection’s expected use case is to enable sharing of a dataset through an origin. Datasets are not a concept in Pelican: here, we assume what an administrator refers to as a “dataset” is simply all objects starting with a given prefix.

Attributes:

- **ID**: Unique, immutable identifier for the collection. Human-adverse naming (randomly generated character string).
- **Name**: Human-friendly name for the collection. Used in web displays and CLI outputs.
- **Description**: Free-form description of the collection. Used in web displays.
- **Visibility**: Public/Private - determines whether the existence of the collection is visible to others.
- **Enable Sharing**: Whether users with collection access can create shares that they manage within the collection.
- **Owner**: A user record that is responsible for the collection itself. The only entity that can delete or transfer ownership of the collection.
- **Administrator**: A user or group record that can make changes to the collection (rename, change description, change access control). Cannot delete or transfer ownership.
- **Access control**: A list of groups and associated access (read/write) they are permitted.

The exported namespace controls whether public reads are permitted. *However*, collections can allow reads or writes by all users. Visually, this can be indicated via a checkbox or presenting a virtual “all-authenticated-users” group in the ACL selection.

The example usage scenario is allowing a PI to have a storage area for their group. The origin administrator would create a collection, making the PI an owner. The group of PI’s postdocs would be the administrator of the collection. This means the PI, other than taking responsibility, is not involved in the day-to-day management. The postdocs would add the group’s undergraduates to a read-only group and the graduate students to a read-write group.

# Shares

A share is a special type of collection that can be created and managed by users who otherwise lack the privilege to create a collection. When data is accessed via the share, it’s done impersonating the owner. The intent is to allow users to share or delegate access that they have to their collaborators.

Users creating a share will frequently want to mint a new group to receive its access. **Group creation is open to any authenticated user** for exactly this reason (see `docs/user-group-design.md`); a self-created group can be used freely as a target in collection ACLs and share ACLs. What a self-created group **cannot** do is automatically match an operator's `Issuer.AuthorizationTemplates` rule or `Server.*AdminGroups` config — those surfaces use the group *name* as bearer authority, and only an admin / user-admin may flip the group's `auth_template_eligible` bit to opt the group into them.

In addition to being a collection, a share has:

- **A parent collection**: The ID of the parent collection the share is tied to.

Special rules apply to shares:

- When calculating access control for access token creation (note: this should also be executed for refresh flows), the share must be intersected with the owner’s access to the collection. A share owner that lost access to the collection - or was downgraded from read-write to read-only - should not be able to delegate out.
- Not supported for XRootD-based POSIX / multi-user backends.
- When the multiuser backend interacts with a token generated for the share, it *must* interact as the owner of the share, not the owner of the token. To differentiate what scopes come from “normal” access versus share-based access, introduce a new `share.access` scope. The presence of the scope `share.access:/$ID` indicates that, inside all prefixes from the share with `$ID`, access the data as the owner of the share.
