import { secureFetch } from '@/helpers/login';
import { API_V1_BASE_URL } from '../constants';
import { fetchApi } from '@/helpers/api';

// One small service handles every shape of invite link (group-join,
// password-set, ...) because the backend deliberately exposes them as a
// unified concept. Per-kind endpoints are intentional — group invites
// require the caller to be authenticated (we need a user to add to the
// group), password invites do not (the token IS the credential).

export type InviteKind = 'group' | 'password' | 'collection_ownership';

export interface InviteInfo {
  kind: InviteKind;
  expiresAt: string;
  isSingleUse: boolean;
  groupId?: string;
  /** Machine-readable name for group-kind invites. Used by the redeem
   * UI to tell the user which group they're about to join. */
  groupName?: string;
  /** Optional human label for group-kind invites. */
  groupDisplayName?: string;
  /** Slug + name + namespace for collection-ownership invites —
   * drive the "Accept ownership of <X> (<namespace>)?" confirmation
   * page. The namespace is what the recipient is actually claiming
   * authority over, so it MUST be visible at confirm time. */
  collectionId?: string;
  collectionName?: string;
  collectionNamespace?: string;
}

export interface InviteLinkBase {
  id: string;
  kind: InviteKind;
  groupId: string;
  targetUserId: string;
  createdBy: string;
  authMethod: string;
  authMethodId?: string;
  createdAt: string;
  updatedAt: string;
  expiresAt: string;
  isSingleUse: boolean;
  redeemedBy: string;
  redeemedAt: string | null;
  revoked: boolean;
  /** Public short identifier — first few chars of the plaintext token.
   * Safe to display; not a credential. */
  tokenPrefix: string;
}

export interface InviteLinkCreated extends InviteLinkBase {
  /** Plaintext token, shown only once at creation. */
  inviteToken: string;
}

const InviteService = {
  // Pre-redemption probe: tells the redemption UI which form to render
  // (password entry vs. confirm-join-group). Does not consume the token.
  // 404 covers all invalid-token cases without distinguishing causes.
  info: async (token: string): Promise<InviteInfo> => {
    const r = await fetchApi(() =>
      fetch(
        `${API_V1_BASE_URL}/invites/info?token=${encodeURIComponent(token)}`
      )
    );
    return await r.json();
  },

  // Group-kind redeem. Caller must be authenticated; the invite adds the
  // calling user to the link's group.
  redeem: async (token: string): Promise<void> => {
    await fetchApi(
      async () =>
        await secureFetch(`${API_V1_BASE_URL}/invites/redeem`, {
          method: 'POST',
          body: JSON.stringify({ token }),
          headers: { 'Content-Type': 'application/json' },
        })
    );
  },

  // Password-kind redeem. NO authentication on this call: the token IS
  // the credential. Password length is enforced server-side (>= 8).
  redeemPassword: async (token: string, password: string): Promise<void> => {
    await fetchApi(
      async () =>
        await fetch(`${API_V1_BASE_URL}/invites/redeem/password`, {
          method: 'POST',
          body: JSON.stringify({ token, password }),
          headers: { 'Content-Type': 'application/json' },
        })
    );
  },

  // Owner/admin: mint a group-join invite link for `groupId`. Recipients
  // who already have an account are added to the group on redeem; new
  // users go through the standard OIDC/login bootstrap first. Use
  // isSingleUse=true for one-shot invites tied to a specific person and
  // false for "share with the team" links.
  createGroupInvite: async (
    groupId: string,
    opts: { isSingleUse?: boolean; expiresIn?: string } = {}
  ): Promise<InviteLinkCreated> => {
    const r = await fetchApi(
      async () =>
        await secureFetch(`${API_V1_BASE_URL}/groups/${groupId}/invites`, {
          method: 'POST',
          body: JSON.stringify({
            isSingleUse: opts.isSingleUse ?? false,
            expiresIn: opts.expiresIn ?? '',
          }),
          headers: { 'Content-Type': 'application/json' },
        })
    );
    return await r.json();
  },

  // Admin-only: mint a single-use password-set invite for `userId`.
  // expiresIn is a Go duration string (e.g. "168h"); empty defers to the
  // server's configured default.
  createPasswordInvite: async (
    userId: string,
    expiresIn?: string
  ): Promise<InviteLinkCreated> => {
    const r = await fetchApi(
      async () =>
        await secureFetch(
          `${API_V1_BASE_URL}/users/${userId}/password-invite`,
          {
            method: 'POST',
            body: JSON.stringify(expiresIn ? { expiresIn } : {}),
            headers: { 'Content-Type': 'application/json' },
          }
        )
    );
    return await r.json();
  },

  // Admin-only: list password invites (live + historical) for one user.
  listPasswordInvites: async (userId: string): Promise<InviteLinkBase[]> => {
    const r = await fetchApi(() =>
      fetch(`${API_V1_BASE_URL}/users/${userId}/password-invites`)
    );
    return await r.json();
  },
};

export default InviteService;
