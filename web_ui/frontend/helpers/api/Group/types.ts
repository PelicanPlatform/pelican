import type { User } from '@/helpers/api/User';

export interface Group {
  id: string;
  name: string;
  description: string;
  members: User[];
  createdBy: string;
  createdAt: string;
}

export type GroupPost = Omit<Group, 'members' | 'createdBy' | 'createdAt'>;

export type GroupPatch = Partial<GroupPost>;
