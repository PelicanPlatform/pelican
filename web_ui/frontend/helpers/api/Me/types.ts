import type { User } from '@/helpers/api/User';
import type { Group } from '@/helpers/api/Group';

// Me is identical in shape to a User record; the distinction is that the
// /me endpoints always return the *calling* user.
export type Me = User;

// PATCH /me only accepts displayName today. Username, sub, issuer, and the
// user_identities are admin-only.
export interface MePatch {
  displayName?: string;
}

// Group as returned by GET /me/groups. Members are not included by /me/groups
// (would leak other users); the response is the bare group metadata.
export type MyGroup = Omit<Group, 'members'>;
