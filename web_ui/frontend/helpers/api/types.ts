export interface ApiService<
  GET = unknown,
  POST = never,
  PATCH = never,
  PUT = never,
  GETFULL extends GET = GET,
> {
  id: string;
  getOne?: (key: ApiID) => Promise<GETFULL>;
  getAll?: () => Promise<GET[]>;
  post?: (data: POST) => Promise<GET>;
  put?: (key: ApiID, data: PUT) => Promise<GET>;
  patch?: (key: ApiID, data: PATCH) => Promise<void>;
  delete?: (key: ApiID) => Promise<void>;
}

export type ApiID = string | number;

export * from './User/types';
export * from './Group/types';
export * from './GroupMember/types';
