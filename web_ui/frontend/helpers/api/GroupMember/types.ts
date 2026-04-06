import { User } from '@/helpers/api/User';

export interface GroupMember {
  groupId: string;
  userId: string;
  user: User;
  createdBy: string;
  createdAt: string;
}

export type GroupMemberPost = Omit<
  GroupMember,
  'user' | 'addedBy' | 'addedAt' | 'groupId'
>;
