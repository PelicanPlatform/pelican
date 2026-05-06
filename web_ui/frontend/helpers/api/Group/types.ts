import type { User } from '@/helpers/api/User';

// GroupMembership wraps a user in a group: the membership row from
// `group_members`, with the User itself nested. The backend serializes
// `Group.Members` as a list of these (NOT a list of bare Users), so the
// UI must dereference `.user` for the actual identity.
export interface GroupMembership {
  groupId: string;
  userId: string;
  user: User;
  createdBy: string;
  createdAt: string;
}

export interface Group {
  id: string;
  // name is the machine-readable identifier; renames are admin-only.
  name: string;
  // displayName is the human label, owner-editable. UIs should fall
  // back to `name` when this is empty.
  displayName: string;
  description: string;
  members: GroupMembership[];
  createdBy: string;
  createdAt: string;
  // createdForCollectionId, when set, ties this group to a specific
  // collection's onboarding pass — a later collection-ownership
  // transfer cascades to it. Read-only from the client's perspective;
  // set on POST and never updated thereafter.
  createdForCollectionId?: string;
  // authTemplateEligible gates whether the group's name is allowed to
  // match Issuer.AuthorizationTemplates and the Server.*AdminGroups
  // config lists. Settable only by an admin / user-admin (server-side
  // gate); user-created groups default to false. Pre-existing groups
  // (before user-driven creation was opened) are migrated to true.
  authTemplateEligible?: boolean;
}

export type GroupPost = Omit<Group, 'members' | 'createdBy' | 'createdAt'>;

export type GroupPatch = Partial<GroupPost>;
