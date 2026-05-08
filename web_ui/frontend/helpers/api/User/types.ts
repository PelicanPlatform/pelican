export interface User {
  id: string;
  username: string;
  sub: string;
  issuer: string;
  createdAt: string;
}

export type UserPost = Omit<User, 'id' | 'createdAt'>;

export type UserPatch = Partial<Omit<User, 'createdAt'>>;
