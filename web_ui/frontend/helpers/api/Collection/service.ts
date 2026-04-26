import { secureFetch } from '@/helpers/login';
import { API_V1_BASE_URL } from '../constants';
import { fetchApi } from '@/helpers/api';
import {
  CollectionAcl,
  CollectionAclGrant,
  CollectionPost,
  CollectionSummary,
} from './types';

// Collections live under /api/v1.0/origin_ui/collections (origin server's
// own UI surface), not under the server-wide /api/v1.0/groups path. The
// service mirrors that split — ACL grants point at *groups* but the
// collection itself is an origin-local concept.
const COLLECTIONS_BASE = `${API_V1_BASE_URL}/origin_ui/collections`;

const CollectionService = {
  id: 'Collections',

  // List the collections this caller can see. The backend filters by
  // ACL membership; the owned-collections page (/origin/owned/)
  // narrows further to "collections I own" client-side via the
  // `owner` field.
  list: async (): Promise<CollectionSummary[]> => {
    const r = await fetchApi(() => fetch(COLLECTIONS_BASE));
    return await r.json();
  },

  getOne: async (id: string): Promise<CollectionSummary> => {
    const r = await fetchApi(() => fetch(`${COLLECTIONS_BASE}/${id}`));
    return await r.json();
  },

  // Create a collection. The caller becomes the implicit owner (the
  // backend records their username on the row). Returns the new
  // collection; the response also includes the auto-generated owner
  // ACL pointing at the caller's personal `user-<username>` group.
  create: async (body: CollectionPost): Promise<CollectionSummary> => {
    const r = await fetchApi(
      async () =>
        await secureFetch(COLLECTIONS_BASE, {
          method: 'POST',
          body: JSON.stringify(body),
          headers: { 'Content-Type': 'application/json' },
        })
    );
    return await r.json();
  },

  // Patch a subset of the collection's mutable fields (name,
  // description, visibility, ownerId, adminId). Unspecified fields
  // are left alone server-side. Owner / admin transfers go through
  // this same surface — the backend re-gates them so a write-ACL
  // holder can't elevate themselves.
  update: async (
    id: string,
    patch: Partial<{
      name: string;
      description: string;
      visibility: 'private' | 'public';
      ownerId: string;
      adminId: string;
    }>
  ): Promise<void> => {
    await fetchApi(
      async () =>
        await secureFetch(`${COLLECTIONS_BASE}/${id}`, {
          method: 'PATCH',
          body: JSON.stringify(patch),
          headers: { 'Content-Type': 'application/json' },
        })
    );
  },

  delete: async (id: string): Promise<void> => {
    await fetchApi(
      async () =>
        await secureFetch(`${COLLECTIONS_BASE}/${id}`, { method: 'DELETE' })
    );
  },

  // List the ACL rows attached to a collection. Each row points at a
  // *group* (by name) with a role; the owned-collections page
  // (/origin/owned/) uses this to resolve "what groups are wired
  // to this collection?".
  listAcls: async (id: string): Promise<CollectionAcl[]> => {
    const r = await fetchApi(() => fetch(`${COLLECTIONS_BASE}/${id}/acl`));
    return await r.json();
  },

  // Grant a single (group, role) ACL on a collection. The backend
  // accepts either group slug OR group name and canonicalises to the
  // name on write — pass either, the resulting row will store the name.
  grantAcl: async (
    collectionId: string,
    grant: CollectionAclGrant
  ): Promise<void> => {
    await fetchApi(
      async () =>
        await secureFetch(`${COLLECTIONS_BASE}/${collectionId}/acl`, {
          method: 'POST',
          body: JSON.stringify(grant),
          headers: { 'Content-Type': 'application/json' },
        })
    );
  },

  // Candidate owners — the union of (current owner, admin-group
  // members, ACL-group members) for use in the edit page's owner
  // picker. Reachable by anyone who can read the collection; the
  // server returns UserCard rows so non-user-admin callers never see
  // more than the public-safe (id, username, displayName) projection.
  // Callers with server.user_admin should prefer GET /users for a
  // global picker.
  candidateOwners: async (
    collectionId: string
  ): Promise<{ id: string; username: string; displayName: string }[]> => {
    const r = await fetchApi(() =>
      fetch(`${COLLECTIONS_BASE}/${collectionId}/candidate-owners`)
    );
    return await r.json();
  },

  // Mint a single-use ownership-transfer invite link for the
  // collection. When the recipient redeems the link, ownership
  // transfers from the caller to the redeemer. The link's
  // expiresIn is a Go-style duration ("168h" = 7 days, etc.); the
  // server forces single-use regardless of any IsSingleUse field
  // — ownership transfer is one-shot by definition.
  createOwnershipInvite: async (
    collectionId: string,
    body: { expiresIn?: string }
  ): Promise<{
    id: string;
    inviteToken: string;
    expiresAt: string;
    isSingleUse: boolean;
  }> => {
    const r = await fetchApi(
      async () =>
        await secureFetch(
          `${COLLECTIONS_BASE}/${collectionId}/ownership-invites`,
          {
            method: 'POST',
            body: JSON.stringify(body),
            headers: { 'Content-Type': 'application/json' },
          }
        )
    );
    return await r.json();
  },

  // Redeem a collection-ownership invite. The redeemer becomes the
  // new owner of the referenced collection. Server-side single-use
  // guarantees the link cannot be replayed after a successful
  // transfer.
  redeemOwnershipInvite: async (
    token: string
  ): Promise<{ collectionId: string; previousOwnerId: string }> => {
    const r = await fetchApi(
      async () =>
        await secureFetch(
          `${API_V1_BASE_URL}/invites/redeem/collection-ownership`,
          {
            method: 'POST',
            body: JSON.stringify({ token }),
            headers: { 'Content-Type': 'application/json' },
          }
        )
    );
    return await r.json();
  },

  // Revoke a (group, role) ACL row. The role is required because the
  // primary key is (collection_id, group_id, role) — a single group
  // may carry both `read` and `write` rows.
  revokeAcl: async (
    collectionId: string,
    revoke: { groupId: string; role: string }
  ): Promise<void> => {
    await fetchApi(
      async () =>
        await secureFetch(`${COLLECTIONS_BASE}/${collectionId}/acl`, {
          method: 'DELETE',
          body: JSON.stringify(revoke),
          headers: { 'Content-Type': 'application/json' },
        })
    );
  },
};

export default CollectionService;
