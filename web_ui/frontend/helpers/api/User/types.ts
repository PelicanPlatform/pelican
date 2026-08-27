export interface User {
  id: string;
  username: string;
  sub: string;
  issuer: string;
  displayName?: string;
  createdAt: string;
  // Server-derived: true when a local password is set on the account.
  // The hash itself is never exposed.
  hasPassword?: boolean;
  // AUP acceptance state, surfaced for the admin edit UI. Empty
  // string means no acceptance recorded; otherwise this is the
  // version hash of the AUP text the user agreed to.
  aupVersion?: string;
  aupAgreedAt?: string | null;
}

// UserPost has two flavors:
//   * Local user: just username (sub/issuer auto-derived server-side).
//     No password field — admins do NOT set passwords. After creation, mint
//     a password-set invite via InviteService.createPasswordInvite() and
//     hand the link to the user.
//   * External (OIDC) user: username + sub + issuer.
// Both flavors may set displayName.
export type UserPost = {
  username: string;
  sub?: string;
  issuer?: string;
  displayName?: string;
};

export type UserPatch = Partial<Omit<User, 'createdAt'>>;
