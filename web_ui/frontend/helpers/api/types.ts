export interface ApiService<
  GET = unknown,
  POST = never,
  PATCH = never,
  PUT = never,
  GETFULL extends GET = GET
> {
  id: string;
  getOne?: (id?: ApiID) => Promise<GETFULL | undefined>;
  getAll?: () => Promise<GET[] | undefined>;
  post?: (data: POST) => Promise<GET | undefined>;
  put?: (id: ApiID, data: PUT) => Promise<GET | undefined>;
  patch?: (id: ApiID, data: PATCH) => Promise<GET | undefined>;
  delete?: (id: ApiID) => Promise<void>;
}

export type ApiID = string | number;

export * from './User/types';
