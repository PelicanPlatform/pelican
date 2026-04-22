import type { User } from '@/helpers/api/User';

export interface GroupMember {
  groupId: string;
  userId: string;
  user: User;
  createdBy: string;
  createdAt: string;
}

export type GroupMemberPost = Omit<
  GroupMember,
  'user' | 'createdBy' | 'createdAt' | 'groupId'
>;
