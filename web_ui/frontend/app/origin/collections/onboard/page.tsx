/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

'use client';

// Single-page onboarding flow for a new collection. Per ticket #3298 the
// admin should be able to, in one form:
//
//   1. Create the collection (name + namespace + visibility);
//   2. Decide who owns it — keep yourself, pick another existing user,
//      create a new account inline, OR mint a single-use ownership-
//      transfer invite that the recipient redeems to take ownership
//      themselves (you stop being the owner the moment they accept);
//   3. Stand up to three groups for it (typically admin / writer /
//      reader). Each row may either create a new group OR re-use an
//      existing one the caller can see;
//   4. Wire those groups onto the collection's ACL with the matching
//      role and (for newly-created groups) transfer ownership of each
//      to the resolved collection owner.
//
// All steps run sequentially against existing endpoints; this page is
// a frontend assembly, not a backend feature. Errors surface
// immediately and the form pauses with whatever was already created
// still listed in the result panel, so the admin can pick up the
// pieces (delete partial state, retry, ...) rather than starting over.

import React, { useContext, useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Autocomplete,
  Box,
  Breadcrumbs,
  Button,
  Chip,
  Divider,
  FormControl,
  IconButton,
  InputLabel,
  MenuItem,
  Paper,
  Radio,
  RadioGroup,
  FormControlLabel,
  Select,
  Stack,
  Switch,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import useSWR from 'swr';

import AuthenticatedContent from '@/components/layout/AuthenticatedContent';
import { AlertDispatchContext } from '@/components/AlertProvider';
import { alertOnError } from '@/helpers/util';
import {
  CollectionAclRole,
  CollectionService,
  CollectionVisibility,
  GroupService,
  InviteService,
  MeService,
  UserService,
} from '@/helpers/api';
import type { Me } from '@/helpers/api';
import type { User as ApiUser } from '@/helpers/api/User/types';
import type { Group as ApiGroup } from '@/helpers/api/Group/types';
import { getUser } from '@/helpers/login';
import { hasScope } from '@/index';
// Slim "just the FederationPrefix list" endpoint — see
// origin/exports.go's handleExportPrefixes. We can't reuse the
// /origin_ui/exports endpoint here because it's gated to system
// admins (it returns storage credentials and registry edit-URL
// tokens); collection-admins running this form would 403 and the
// dropdown would be empty, leading to the misleading "no exports
// configured" warning.
const fetchExportPrefixes = async (): Promise<string[]> => {
  const r = await fetch('/api/v1.0/origin_ui/exports/prefixes');
  if (!r.ok) {
    throw new Error(`Failed to fetch export prefixes: ${r.statusText}`);
  }
  const json = await r.json();
  return Array.isArray(json?.prefixes) ? json.prefixes : [];
};

// Per-row source: either we're creating a brand-new group, or the
// admin is re-using one that already exists (and is visible to them
// via /groups, which the backend filters by membership/admin/owner
// for non-user-admins).
type GroupSource = 'create' | 'existing';

// One row in the groups section. Each role gets a default row but the
// admin can disable it or flip its source between create-new and
// pick-existing. The `source` discriminates which subset of the row's
// fields actually drives the submit pipeline.
interface GroupRow {
  enabled: boolean;
  role: CollectionAclRole;
  source: GroupSource;
  // create-mode: machine-readable name (admin-only authorization
  // handle). Validated server-side per database/identifiers.go; we
  // leave that check authoritative rather than re-implementing the
  // regex here.
  name: string;
  // create-mode: optional human label.
  displayName: string;
  // create-mode: free-form description.
  description: string;
  // nameDirty / displayNameDirty mark fields the admin has typed into,
  // so the auto-suggest effect (which derives name + displayName from
  // the collection name) doesn't clobber a deliberate edit. Both reset
  // when the field is cleared back to empty.
  nameDirty: boolean;
  displayNameDirty: boolean;
  // existing-mode: the picked Group. Stored as the full row (not just
  // the ID) so the autocomplete keeps its label without a re-fetch.
  existingGroup: ApiGroup | null;
}

// slugify converts a free-form collection name into something close to
// what database/identifiers.go's ValidateIdentifier accepts: no
// whitespace, no '/', no leading punctuation, no '..'. The backend
// stays authoritative, but the suggestion shouldn't itself be invalid.
const slugify = (s: string): string =>
  s
    .trim()
    .replace(/[\s/]+/g, '-')
    // Drop everything outside the friendly identifier alphabet. Per
    // the validator we could keep more, but A–Za–z0–9._- is what
    // ValidateIdentifier accepts unconditionally.
    .replace(/[^A-Za-z0-9._-]+/g, '')
    .replace(/-+/g, '-')
    .replace(/^[._-]+|[._-]+$/g, '');

// Per-role suffixes for both the slug and the display name. The
// "owner" form-row maps to the collection's AdminID (an admin group
// — full management authority); writers/readers map to ACL grants.
// The slug suffixes match the role's wire word ("-admins" / "-writers"
// / "-readers") so an admin reading the resulting group names knows
// exactly what each one buys.
const roleSlugSuffix = (r: CollectionAclRole): string =>
  r === 'owner' ? 'admins' : r === 'write' ? 'writers' : 'readers';
const roleWord = (r: CollectionAclRole): string =>
  r === 'owner' ? 'Admins' : r === 'write' ? 'Writers' : 'Readers';

const suggestedGroupName = (
  collectionName: string,
  role: CollectionAclRole
): string => {
  const slug = slugify(collectionName);
  return slug ? `${slug}-${roleSlugSuffix(role)}` : '';
};

const suggestedGroupDisplayName = (
  collectionName: string,
  role: CollectionAclRole
): string => {
  const trimmed = collectionName.trim();
  return trimmed ? `${trimmed} ${roleWord(role)}` : '';
};

// What we hand back after a successful onboarding. Stored in component
// state so the admin can copy the invite URL exactly once.
interface OnboardResult {
  collectionId: string;
  collectionName: string;
  // The owner that was set on the collection. `userId` is the slug,
  // `username` is the display handle. `created` is true when this user
  // was created inline by the form (vs. picked from the existing list,
  // left as the calling admin, or pending-an-invite-redemption).
  // Optional: half-failure paths (onboarding stopped before ownership
  // was wired) record what was achieved without inventing data for
  // fields that were never set.
  owner?: { userId: string; username: string; created: boolean };
  // Groups wired onto the collection, in submission order. `reused` is
  // true when the row pointed at an existing group rather than creating
  // a new one (the form skips the POST /groups step in that case).
  groups: {
    groupId: string;
    groupName: string;
    role: CollectionAclRole;
    reused: boolean;
  }[];
  // Plaintext URL for the ownership-transfer invite — minted when
  // the admin picks the "invite" owner mode. Single-use; redemption
  // atomically moves Collection.OwnerID from the calling admin to
  // the redeemer. Empty when owner mode is anything else.
  ownerInviteUrl: string;
  // Plaintext URL for the password-set invite, present only when a
  // brand-new local user was created here. The new user follows it
  // once to choose their own password — admins never see it.
  passwordInviteUrl?: string;
  // True when onboarding stopped mid-flight (e.g. group-create failed
  // because the auto-suggested name collided with an existing group).
  // The result panel renders an "incomplete" heading + warning Alert
  // instead of the success-styled "<X> is ready" so the admin sees
  // the actual state at a glance — the error popup is necessary
  // context but not enough on its own.
  partial?: boolean;
  // One-line summary of which step failed. Only populated when
  // partial is true. The exact error message comes through the
  // alert dispatcher; this is just the "where in the pipeline".
  partialReason?: string;
}

// Owner picker mode.
//   self     — keep the calling admin as owner (backend's default)
//   existing — transfer to an existing user from /users
//   new      — create a new user inline and transfer to them
//   invite   — calling admin stays the owner *for now*; mint a
//              single-use ownership-transfer invite. On redemption
//              the recipient becomes the new owner and the calling
//              admin loses ownership at the same moment. Used when
//              the eventual owner isn't known up front.
// `existing` and `new` require server.user_admin. `invite` works for
// any caller with collection-management authority — the recipient
// must be able to log in (existing account or OIDC self-enroll on
// first login).
type OwnerMode = 'self' | 'existing' | 'new' | 'invite';

// 168h = 7 days, the same default the per-group invite UI uses.
const DEFAULT_INVITE_EXPIRY = '168h';

const Page = () => (
  // Gate matches the backend: POST /origin_ui/collections requires
  // server.collection_admin OR server.admin (admin implies it).
  // Admit on EITHER role==='admin' OR the explicit scope so a system
  // admin always lands on the form regardless of how their effective
  // scope set was computed, and a non-admin holding only the targeted
  // scope still gets in. Same pattern used by /settings/users.
  <AuthenticatedContent
    redirect={true}
    allowedRoles={['admin']}
    anyScopes={['server.collection_admin']}
  >
    <OnboardForm />
  </AuthenticatedContent>
);

const OnboardForm: React.FC = () => {
  const dispatch = useContext(AlertDispatchContext);
  const router = useRouter();

  // Whoami + the calling user's record. We need both: `who` is the
  // /whoami response (gives us the scope set and the role label),
  // `me` is the User row (gives us the ID slug we need when the admin
  // accepts the default "yourself" owner option). Both are cheap and
  // the form can render against partial data.
  const { data: who } = useSWR('getUser', getUser);
  const { data: me } = useSWR<Me | undefined>('me', () =>
    alertOnError(MeService.get, 'Failed to load your account', dispatch)
  );
  // user_admin gates the "pick existing user" autocomplete and the
  // inline "create new user" form, because /users (list + create)
  // requires that scope server-side. admin implies user_admin in
  // EffectiveScopesForIdentity, so a system admin gets both paths.
  const canManageUsers =
    who?.role === 'admin' || hasScope(who, 'server.user_admin');

  // Collection metadata.
  const [name, setName] = useState('');
  // Namespace is split into prefix (one of the origin's exports) and
  // suffix (the rest the admin types). The backend's
  // namespaceWithinExport check accepts either an exact match or a
  // strict path-descendant of an exported FederationPrefix; splitting
  // the input that way means the admin can't accidentally type a
  // prefix that isn't exported. The submitted value is the joined
  // string (computed below).
  const [namespacePrefix, setNamespacePrefix] = useState('');
  const [namespaceSuffix, setNamespaceSuffix] = useState('');
  const [description, setDescription] = useState('');
  const [visibility, setVisibility] = useState<CollectionVisibility>('private');

  // Pull the origin's configured FederationPrefix list so the prefix
  // dropdown reflects what's actually advertised. Cached via SWR;
  // failures bubble through the alert dispatcher rather than blocking
  // the form. Uses /origin_ui/exports/prefixes — a public-info slice
  // of the full exports endpoint — so a collection-admin (not a
  // system admin) can also drive this form.
  const { data: exportPrefixesData } = useSWR(
    'origin/exports/prefixes',
    () =>
      alertOnError(
        fetchExportPrefixes,
        'Failed to load origin exports',
        dispatch
      ),
    { revalidateOnFocus: false }
  );
  const exportPrefixes = useMemo<string[]>(
    () => exportPrefixesData ?? [],
    [exportPrefixesData]
  );

  // When exports load, auto-pick the only one (the common single-export
  // origin case) so the admin sees a populated form rather than an
  // empty dropdown. If the previously-selected prefix is no longer
  // exported (e.g. the operator just removed it from config), fall
  // back to the first remaining prefix so submission isn't poisoned
  // by a stale value.
  useEffect(() => {
    if (exportPrefixes.length === 0) return;
    if (!namespacePrefix) {
      if (exportPrefixes.length === 1) {
        setNamespacePrefix(exportPrefixes[0]);
      }
      return;
    }
    if (!exportPrefixes.includes(namespacePrefix)) {
      setNamespacePrefix(exportPrefixes[0]);
    }
  }, [exportPrefixes, namespacePrefix]);

  // The full namespace as the backend will see it. Trimming and
  // collapsing leading/trailing slashes on the suffix lets the admin
  // type "team-a" or "/team-a/data" interchangeably without producing
  // "//" segments.
  const namespace = useMemo<string>(() => {
    if (!namespacePrefix) return '';
    const cleanPrefix = namespacePrefix.replace(/\/+$/, '');
    const cleanSuffix = namespaceSuffix.trim().replace(/^\/+|\/+$/g, '');
    return cleanSuffix ? `${cleanPrefix}/${cleanSuffix}` : cleanPrefix;
  }, [namespacePrefix, namespaceSuffix]);

  // --- Owner picker ---
  // Three modes (see OwnerMode): keep the calling admin (default),
  // pick an existing user, or create a new one inline. Both non-self
  // modes need /users access (server-side gate is user_admin), so they
  // fall back to "self" when the admin lacks user_admin.
  const [ownerMode, setOwnerMode] = useState<OwnerMode>('self');
  const [ownerExistingUser, setOwnerExistingUser] = useState<ApiUser | null>(
    null
  );
  // Inline new-user fields. We mirror the same two-flavor model the
  // /users POST handler accepts: empty sub+issuer = local user (admin
  // mints a password-set invite right after); non-empty pre-binds an
  // OIDC identity so the user's first SSO login attaches to the row.
  const [newUserUsername, setNewUserUsername] = useState('');
  const [newUserDisplayName, setNewUserDisplayName] = useState('');
  const [newUserSub, setNewUserSub] = useState('');
  const [newUserIssuer, setNewUserIssuer] = useState('');

  // Pull the user list only when the admin opens the picker — the
  // server gates /users on user_admin and we don't want to 403 the
  // form on mount for a collection-admin who never opens the panel.
  // SWR caches by the truthy key so flipping the mode back and forth
  // doesn't re-fetch.
  const userListEnabled = canManageUsers && ownerMode === 'existing';
  const { data: allUsers, isLoading: usersLoading } = useSWR<
    ApiUser[] | undefined
  >(userListEnabled ? 'users:all' : null, () =>
    alertOnError(UserService.getAll, 'Failed to load users', dispatch)
  );

  // If the admin lacks user_admin and somehow ends up in a non-self
  // mode (e.g. via stale state), bounce them back to "self" — the
  // submit would 403 otherwise and the result panel would be empty.
  useEffect(() => {
    if (!canManageUsers && ownerMode !== 'self') {
      setOwnerMode('self');
    }
  }, [canManageUsers, ownerMode]);

  // The three group rows. Defaults map to the common pattern (one
  // admin, one writer, one reader) but the admin can disable any
  // before submitting. Each row defaults to creating a new group;
  // flipping `source` to 'existing' switches it to the picker.
  const [groups, setGroups] = useState<GroupRow[]>([
    {
      enabled: true,
      role: 'owner',
      source: 'create',
      name: '',
      displayName: '',
      description:
        'Admin group — members can manage permissions and edit the collection',
      nameDirty: false,
      displayNameDirty: false,
      existingGroup: null,
    },
    {
      enabled: false,
      role: 'write',
      source: 'create',
      name: '',
      displayName: '',
      description: 'Writers — can upload objects into the collection.',
      nameDirty: false,
      displayNameDirty: false,
      existingGroup: null,
    },
    {
      enabled: false,
      role: 'read',
      source: 'create',
      name: '',
      displayName: '',
      description: 'Readers — can list and read objects in the collection.',
      nameDirty: false,
      displayNameDirty: false,
      existingGroup: null,
    },
  ]);

  // Re-suggest group name + display name whenever the collection name
  // changes, but ONLY for fields the admin hasn't deliberately edited
  // (nameDirty / displayNameDirty). This is the "Test Collection →
  // Test-Collection-owners" auto-fill. Once the admin types into a
  // field it sticks until they clear it back to empty.
  useEffect(() => {
    setGroups((prev) =>
      prev.map((g) => ({
        ...g,
        name: g.nameDirty ? g.name : suggestedGroupName(name, g.role),
        displayName: g.displayNameDirty
          ? g.displayName
          : suggestedGroupDisplayName(name, g.role),
      }))
    );
    // We only want to react to the collection name itself; group
    // updates are managed separately and would otherwise loop here.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [name]);

  // Owner-invite single-use toggle. Only meaningful when ownerMode is
  // 'invite' (the recipient claims management authority by joining
  // the admin group). Defaults to single-use because that's what the
  // "send to a specific person" use case wants.
  const [ownerInviteSingleUse, setOwnerInviteSingleUse] = useState(true);

  // Group picker source. The /groups list endpoint already returns the
  // right set per-caller (system admins + user_admins see everything;
  // everyone else sees groups they own / admin / are a member of), so
  // we don't need a separate filter here. Loaded only when at least
  // one row is in 'existing' mode to avoid an unnecessary fetch on a
  // pure create-everything onboarding.
  const anyExistingPicker = groups.some(
    (g) => g.enabled && g.source === 'existing'
  );
  const { data: visibleGroups, isLoading: groupsLoading } = useSWR<
    ApiGroup[] | undefined
  >(anyExistingPicker ? 'groups:visible' : null, () =>
    alertOnError(GroupService.getAll, 'Failed to load groups', dispatch)
  );

  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<OnboardResult | null>(null);

  const updateGroup = (idx: number, patch: Partial<GroupRow>) => {
    setGroups((prev) =>
      prev.map((g, i) => (i === idx ? { ...g, ...patch } : g))
    );
  };

  // Inline validation for the submit button. We keep it loose — the
  // backend has the authoritative regex for identifier validity — but
  // surface the obvious "you forgot to fill the group name" case so the
  // submit doesn't stall halfway through.
  const enabledGroups = groups.filter((g) => g.enabled);
  // A row is well-formed when it has the field its source needs:
  // create-mode needs a name typed in; existing-mode needs a picked
  // group from the autocomplete. Either way the backend re-validates.
  const groupsValid = enabledGroups.every((g) =>
    g.source === 'create' ? g.name.trim() !== '' : !!g.existingGroup
  );
  const adminRow = enabledGroups.find((g) => g.role === 'owner');
  // Owner-section validation. "self" is always satisfied. "existing"
  // needs a picked user; "new" needs at least a username — sub +
  // issuer must come paired (matches the backend rule in handleAddUser).
  // "invite" needs an enabled admin group row to point at.
  const newUserPaired =
    (newUserSub.trim() === '' && newUserIssuer.trim() === '') ||
    (newUserSub.trim() !== '' && newUserIssuer.trim() !== '');
  const ownerValid =
    ownerMode === 'self' ||
    (ownerMode === 'existing' && !!ownerExistingUser) ||
    (ownerMode === 'new' && newUserUsername.trim() !== '' && newUserPaired) ||
    // 'invite' mode: the calling admin stays the owner until the
    // recipient redeems the link. No prerequisite — the link points
    // at the just-created collection regardless of group setup.
    ownerMode === 'invite';
  const canSubmit =
    !busy &&
    name.trim() !== '' &&
    namespace.trim() !== '' &&
    groupsValid &&
    ownerValid;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setResult(null);

    // ---- Step 0 — resolve the desired owner. Done first so a failure
    // here doesn't leave a half-built collection behind. The selected
    // user (existing or just-created) becomes the collection's
    // ownerId via PATCH below.
    let ownerInfo: {
      userId: string;
      username: string;
      created: boolean;
      // If we just created a *local* user, mint a password-set invite
      // for them so they can log in. OIDC pre-bind users (sub+issuer
      // supplied) skip this — they log in via SSO instead.
      mintPasswordInvite: boolean;
    } | null = null;
    if (ownerMode === 'self') {
      // Prefer me.id (the slug). Fall back to me.username for display.
      // me may not be loaded yet for first-paint submissions; the
      // backend stamps the caller as owner regardless, so we tolerate
      // an empty slug here and skip the PATCH.
      ownerInfo = me
        ? {
            userId: me.id,
            username: me.username,
            created: false,
            mintPasswordInvite: false,
          }
        : null;
    } else if (ownerMode === 'existing' && ownerExistingUser) {
      ownerInfo = {
        userId: ownerExistingUser.id,
        username: ownerExistingUser.username,
        created: false,
        mintPasswordInvite: false,
      };
    } else if (ownerMode === 'new') {
      const isLocal = newUserSub.trim() === '' && newUserIssuer.trim() === '';
      const newUser = await alertOnError(
        () =>
          UserService.post({
            username: newUserUsername.trim(),
            displayName: newUserDisplayName.trim(),
            sub: isLocal ? undefined : newUserSub.trim(),
            issuer: isLocal ? undefined : newUserIssuer.trim(),
          }),
        'Failed to create user',
        dispatch
      );
      if (!newUser) {
        setBusy(false);
        return;
      }
      ownerInfo = {
        userId: newUser.id,
        username: newUser.username,
        created: true,
        mintPasswordInvite: isLocal,
      };
    }

    // ---- Step 1 — collection. The backend stamps the calling user as
    // the initial owner; if the admin picked someone else, we transfer
    // it via PATCH below.
    const collection = await alertOnError(
      () =>
        CollectionService.create({
          name: name.trim(),
          namespace: namespace.trim(),
          description: description.trim(),
          visibility,
        }),
      'Failed to create collection',
      dispatch
    );
    if (!collection) {
      setBusy(false);
      return;
    }

    // Helper that captures the partial-success state we want to surface
    // when a later step fails. Built once so every early-return below
    // doesn't have to re-spell the OnboardResult literal.
    const ownerForResult: OnboardResult['owner'] = ownerInfo
      ? {
          userId: ownerInfo.userId,
          username: ownerInfo.username,
          created: ownerInfo.created,
        }
      : { userId: '', username: me?.username ?? '', created: false };
    // partialResult builds the onboarding-result object used both for
    // full success and for early-return failure paths. Pass a non-empty
    // reason to mark the result as partial — the result panel keys off
    // that to render an "incomplete" warning instead of the success
    // heading.
    const partialResult = (
      groupsCreated: OnboardResult['groups'],
      ownerInviteUrl = '',
      passwordInviteUrl = '',
      reason = ''
    ): OnboardResult => ({
      collectionId: collection.id,
      collectionName: collection.name,
      owner: ownerForResult,
      groups: groupsCreated,
      ownerInviteUrl,
      passwordInviteUrl,
      partial: reason !== '',
      partialReason: reason || undefined,
    });

    // The "owner of any new groups we create" is the resolved
    // collection owner — that's the user the admin is handing the
    // whole hierarchy to. Falls back to the calling admin (me.id) on
    // owner-mode 'self' and 'invite'; in both cases that user already
    // is the collection's owner.
    const groupOwnerId = ownerInfo?.userId || me?.id || '';

    // ---- Step 1b — transfer collection ownership when the picked
    // user isn't the calling admin. PATCH /collections/:id with
    // ownerId. Skipped when the admin chose "self" / "invite" (or
    // when me wasn't loaded — the backend already stamped them as
    // owner so the row is correct either way).
    if (ownerInfo && ownerInfo.userId && ownerInfo.userId !== me?.id) {
      const transferOk = await alertOnError(
        () =>
          CollectionService.update(collection.id, {
            ownerId: ownerInfo!.userId,
          }).then(() => true),
        `Failed to transfer ownership to "${ownerInfo.username}"`,
        dispatch
      );
      if (!transferOk) {
        setBusy(false);
        setResult(
          partialResult(
            [],
            '',
            '',
            `Could not transfer ownership to "${ownerInfo.username}". The collection was created but is still owned by you.`
          )
        );
        return;
      }
    }

    // ---- Step 2 — groups. Each row is either created fresh (POST
    // /groups + transfer ownership to the resolved collection owner)
    // or resolved to an existing visible group whose ID we already
    // hold. Either way the result feeds the wiring step below.
    const wired: OnboardResult['groups'] = [];
    for (const row of enabledGroups) {
      let groupId = '';
      let groupName = '';
      let reused = false;

      if (row.source === 'existing' && row.existingGroup) {
        groupId = row.existingGroup.id;
        groupName = row.existingGroup.name;
        reused = true;
      } else {
        const grp = await alertOnError(
          () =>
            GroupService.post({
              id: '',
              name: row.name.trim(),
              displayName: row.displayName.trim(),
              description: row.description.trim(),
              // Tie this newly-minted group to the collection so a
              // later ownership transfer cascades to it (per #2C).
              // Existing groups picked from the dropdown are NOT
              // tagged this way — they may be shared elsewhere.
              createdForCollectionId: collection.id,
            } as any),
          `Failed to create group "${row.name}"`,
          dispatch
        );
        if (!grp) {
          // Stop early: the ACL grants below would fail anyway. The
          // collection and any earlier groups remain — the admin can
          // navigate to /groups and clean up if desired. Most common
          // cause: an earlier onboarding (or a manual admin step)
          // already created a group with the same name. Surface that
          // hint so the admin knows what to look for instead of
          // staring at the success-styled panel.
          setBusy(false);
          setResult(
            partialResult(
              wired,
              '',
              '',
              `Could not create group "${row.name}". This often means a group with that name already exists — change the row's name and re-run, or pick "use existing" instead.`
            )
          );
          return;
        }
        groupId = grp.id;
        groupName = row.name.trim();

        // Transfer the new group's ownership to the collection's
        // owner so the same human controls both. We skip when the
        // resolved owner is the calling admin (the backend already
        // stamped them as the group's creator-owner) and when we
        // somehow lack a slug to transfer to.
        if (groupOwnerId && groupOwnerId !== me?.id) {
          const transferred = await alertOnError(
            () =>
              GroupService.transferOwnership(grp.id, {
                ownerId: groupOwnerId,
              }).then(() => true),
            `Failed to transfer "${groupName}" to the collection owner`,
            dispatch
          );
          if (!transferred) {
            setBusy(false);
            setResult(
              partialResult(
                wired,
                '',
                '',
                `Could not transfer the new group "${groupName}" to the collection's owner.`
              )
            );
            return;
          }
        }
      }

      wired.push({ groupId, groupName, role: row.role, reused });

      // Step 3 — wire the group onto the collection. The ownership
      // model is: Owner = user, AdminID = group, ACLs = read/write
      // groups. The "owner" row in this form maps to the AdminID
      // field (full management authority granted to a group); the
      // "write"/"read" rows become CollectionACL entries.
      if (row.role === 'owner') {
        const adminOk = await alertOnError(
          () =>
            CollectionService.update(collection.id, {
              adminId: groupId,
            }).then(() => true),
          `Failed to set admin group "${groupName}" on the collection`,
          dispatch
        );
        if (!adminOk) {
          setBusy(false);
          setResult(
            partialResult(
              wired,
              '',
              '',
              `Could not set "${groupName}" as the collection's admin group.`
            )
          );
          return;
        }
      } else {
        // ACLs are persisted by the *group name* server-side (see
        // GrantCollectionAcl), so we pass the name rather than the slug.
        const aclOk = await alertOnError(
          () =>
            CollectionService.grantAcl(collection.id, {
              groupId: groupName,
              role: row.role,
            }).then(() => true),
          `Failed to grant ${row.role} ACL to "${groupName}"`,
          dispatch
        );
        if (!aclOk) {
          setBusy(false);
          setResult(
            partialResult(
              wired,
              '',
              '',
              `Could not grant ${row.role} access to "${groupName}".`
            )
          );
          return;
        }
      }
    }

    // ---- Step 3b — cascade the collection's admin group onto the
    // *other* freshly-created groups in this onboarding pass. The
    // operator's intent (per demo feedback): one group runs the
    // collection AND every group that came along with it. Without
    // this, after onboarding finishes the admin-group can manage
    // the collection but not the read/write groups attached to it,
    // which forces day-to-day admins to ping the collection owner
    // for every group-membership tweak.
    //
    // We only touch groups we *just created* (reused=false). Groups
    // the operator picked from the existing pool are left alone —
    // they may be shared with other collections, and stomping on
    // their admin group would leak this collection's authority into
    // unrelated places.
    const adminGroupRow = wired.find((g) => g.role === 'owner');
    if (adminGroupRow) {
      for (const row of wired) {
        if (row.reused) continue;
        if (row.groupId === adminGroupRow.groupId) continue;
        const ok = await alertOnError(
          () =>
            GroupService.transferOwnership(row.groupId, {
              adminId: adminGroupRow.groupId,
              adminType: 'group',
            }).then(() => true),
          `Failed to set "${adminGroupRow.groupName}" as admin of "${row.groupName}"`,
          dispatch
        );
        if (!ok) {
          setBusy(false);
          setResult(
            partialResult(
              wired,
              '',
              '',
              `Could not set "${adminGroupRow.groupName}" as the admin group of "${row.groupName}".`
            )
          );
          return;
        }
      }
    }

    // ---- Step 4 — ownership-transfer invite. Only minted when the
    // admin picked the 'invite' owner mode. The calling admin stays
    // the collection owner until the recipient redeems the link;
    // redemption atomically swaps Collection.OwnerID to the
    // redeemer (existing user OR new self-enrolled OIDC user).
    // Single-use is enforced server-side — there is no client
    // toggle for that.
    let ownerInviteUrl = '';
    if (ownerMode === 'invite') {
      const link = await alertOnError(
        () =>
          CollectionService.createOwnershipInvite(collection.id, {
            expiresIn: DEFAULT_INVITE_EXPIRY,
          }),
        'Failed to create ownership-transfer invite',
        dispatch
      );
      if (link) {
        ownerInviteUrl =
          typeof window === 'undefined'
            ? `/view/invite/redeem?token=${encodeURIComponent(link.inviteToken)}`
            : `${window.location.origin}/view/invite/redeem?token=${encodeURIComponent(
                link.inviteToken
              )}`;
      }
    }

    // ---- Step 5 — password-set invite for a freshly-created LOCAL
    // user. OIDC pre-bind users skip this; they authenticate through
    // their IdP. Per the design, admins never see the password — the
    // invite is what the new user follows to choose their own.
    let passwordInviteUrl = '';
    if (ownerInfo && ownerInfo.created && ownerInfo.mintPasswordInvite) {
      const link = await alertOnError(
        () => InviteService.createPasswordInvite(ownerInfo!.userId),
        `Failed to mint password-set invite for "${ownerInfo.username}"`,
        dispatch
      );
      if (link) {
        passwordInviteUrl =
          typeof window === 'undefined'
            ? `/view/invite/redeem?token=${encodeURIComponent(link.inviteToken)}`
            : `${window.location.origin}/view/invite/redeem?token=${encodeURIComponent(
                link.inviteToken
              )}`;
      }
    }

    setResult(partialResult(wired, ownerInviteUrl, passwordInviteUrl));
    setBusy(false);
  };

  // After a successful onboarding the form is replaced with a result
  // panel — re-rendering the form would invite "did I just submit
  // again?" mistakes. Admins click "Back to collections" or "Onboard
  // another" to continue.
  if (result) {
    return (
      <ResultPanel
        result={result}
        onAnother={() => {
          setResult(null);
          setName('');
          setNamespaceSuffix('');
          // Leave namespacePrefix as-is: the admin almost always
          // onboards into the same export, and the auto-pick effect
          // would re-set it on a single-export origin anyway.
          setDescription('');
          setVisibility('private');
          setGroups((prev) =>
            prev.map((g) => ({
              ...g,
              source: 'create',
              name: '',
              displayName: '',
              nameDirty: false,
              displayNameDirty: false,
              existingGroup: null,
            }))
          );
          // Reset owner picker too so the next onboarding doesn't
          // inherit the previous run's user. "self" is the safe
          // default; the picker stays available if they want it.
          setOwnerMode('self');
          setOwnerExistingUser(null);
          setNewUserUsername('');
          setNewUserDisplayName('');
          setNewUserSub('');
          setNewUserIssuer('');
        }}
        onDone={() => router.push('/origin/collections/')}
      />
    );
  }

  return (
    <Box width='100%' maxWidth={760}>
      <Breadcrumbs aria-label='breadcrumb' sx={{ mb: 2 }}>
        <Link href='/origin/collections/'>Collections</Link>
        <Typography color='text.primary'>Onboard</Typography>
      </Breadcrumbs>
      <Typography variant='h4' mb={1}>
        Onboard a new collection
      </Typography>
      <Typography variant='body2' color='text.secondary' mb={3}>
        Create a collection, decide who owns it, and stand up its groups — all
        in one step. Each row can re-use an existing group if you have one; you
        can also wire ACLs by hand later from the collection&apos;s edit page.
      </Typography>

      <form onSubmit={handleSubmit}>
        {/* --- Collection metadata --- */}
        <Paper variant='outlined' sx={{ p: 3, mb: 3 }}>
          <Typography variant='h6' mb={2}>
            Collection
          </Typography>
          <TextField
            label='Name'
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
            fullWidth
            sx={{ mb: 2 }}
            helperText='Short human-readable name.'
          />
          {/*
            Namespace = exported prefix + suffix the admin types. The
            backend's namespaceWithinExport check accepts the prefix
            verbatim or any strict descendant of it; splitting the
            input keeps the admin from inventing a prefix that isn't
            exported. The full path is rendered live below for
            confirmation.
          */}
          <NamespaceField
            prefixes={exportPrefixes}
            prefix={namespacePrefix}
            suffix={namespaceSuffix}
            onPrefixChange={setNamespacePrefix}
            onSuffixChange={setNamespaceSuffix}
            fullPath={namespace}
          />
          <TextField
            label='Description'
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            fullWidth
            multiline
            rows={2}
            sx={{ mb: 2 }}
          />
          <FormControl fullWidth>
            <InputLabel>Visibility</InputLabel>
            <Select
              value={visibility}
              label='Visibility'
              onChange={(e) =>
                setVisibility(e.target.value as CollectionVisibility)
              }
            >
              <MenuItem value='private'>Private</MenuItem>
              <MenuItem value='public'>Public</MenuItem>
            </Select>
          </FormControl>
        </Paper>

        {/* --- Ownership (incl. owner-invite mode) --- */}
        <Paper variant='outlined' sx={{ p: 3, mb: 3 }}>
          <Typography variant='h6' mb={1}>
            Ownership
          </Typography>
          <Typography variant='body2' color='text.secondary' mb={2}>
            Whoever holds ownership can transfer the collection, change its
            admin group, and delete it. Default is <strong>you</strong>. Pick a
            different existing user, create a brand-new account, or mint an
            invite link another user can follow to claim ownership. Ownership
            can also be transferred later from the collection&apos;s edit page.
          </Typography>
          <OwnerSection
            mode={ownerMode}
            onModeChange={setOwnerMode}
            canManageUsers={canManageUsers}
            me={me}
            users={allUsers ?? []}
            usersLoading={usersLoading}
            existingUser={ownerExistingUser}
            onExistingUserChange={setOwnerExistingUser}
            newUserUsername={newUserUsername}
            newUserDisplayName={newUserDisplayName}
            newUserSub={newUserSub}
            newUserIssuer={newUserIssuer}
            onNewUserUsernameChange={setNewUserUsername}
            onNewUserDisplayNameChange={setNewUserDisplayName}
            onNewUserSubChange={setNewUserSub}
            onNewUserIssuerChange={setNewUserIssuer}
            newUserPaired={newUserPaired}
            inviteSingleUse={ownerInviteSingleUse}
            onInviteSingleUseChange={setOwnerInviteSingleUse}
            adminRowEnabled={!!adminRow}
          />
        </Paper>

        {/* --- Groups (up to 3) --- */}
        <Paper variant='outlined' sx={{ p: 3, mb: 3 }}>
          <Typography variant='h6' mb={1}>
            Access Control
          </Typography>
          <Typography variant='body2' color='text.secondary' mb={2}>
            Configure the access and management of the collection. For each
            permission, either create a fresh group OR attach an existing
            one. Disable rows you don&apos;t need; more can be added later
            from the collection&apos;s page.
          </Typography>
          <Stack spacing={2}>
            {groups.map((g, i) => (
              <GroupRowEditor
                key={i}
                row={g}
                onChange={(patch) => updateGroup(i, patch)}
                visibleGroups={visibleGroups ?? []}
                groupsLoading={groupsLoading}
                seesAllGroups={canManageUsers}
              />
            ))}
          </Stack>
        </Paper>

        <Box display='flex' gap={2}>
          <Button type='submit' variant='contained' disabled={!canSubmit}>
            {busy ? 'Onboarding…' : 'Onboard collection'}
          </Button>
          <Link href='/origin/collections/'>
            <Button variant='outlined'>Cancel</Button>
          </Link>
        </Box>
      </form>
    </Box>
  );
};

// NamespaceField composes the prefix dropdown, the slash separator,
// and the suffix input. When only one export is configured we
// collapse the dropdown to a static chip so the form reads "the only
// option / type-in-a-suffix"; otherwise it's a Select with one option
// per FederationPrefix. The full computed path (`prefix/suffix`)
// renders live below so the admin can see exactly what gets submitted.
const NamespaceField: React.FC<{
  prefixes: string[];
  prefix: string;
  suffix: string;
  onPrefixChange: (v: string) => void;
  onSuffixChange: (v: string) => void;
  fullPath: string;
}> = ({
  prefixes,
  prefix,
  suffix,
  onPrefixChange,
  onSuffixChange,
  fullPath,
}) => {
  const noExports = prefixes.length === 0;
  const singleExport = prefixes.length === 1;
  return (
    <Box sx={{ mb: 2 }}>
      <Typography variant='body2' sx={{ mb: 0.5 }}>
        Prefix
      </Typography>
      {noExports ? (
        <Alert severity='warning' sx={{ mb: 1 }}>
          This origin has no configured exports. Configure at least one
          <code> Origin.Exports[*].FederationPrefix</code> entry before
          onboarding a collection — the namespace must live inside an exported
          prefix.
        </Alert>
      ) : (
        <Stack direction='row' spacing={1} alignItems='center'>
          {singleExport ? (
            <Tooltip title='This origin has only one configured export.'>
              <Chip
                label={prefixes[0]}
                sx={{ fontFamily: 'monospace' }}
                variant='outlined'
              />
            </Tooltip>
          ) : (
            <FormControl size='small' sx={{ minWidth: 220 }}>
              <InputLabel>Exported prefix</InputLabel>
              <Select
                value={prefix}
                label='Exported namespace'
                onChange={(e) => onPrefixChange(e.target.value as string)}
              >
                {prefixes.map((p) => (
                  <MenuItem key={p} value={p} sx={{ fontFamily: 'monospace' }}>
                    {p}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          )}
          <Typography variant='body1' fontFamily='monospace'>
            /
          </Typography>
          <TextField
            size='small'
            value={suffix}
            onChange={(e) => onSuffixChange(e.target.value)}
            placeholder='e.g. team-a/data'
            fullWidth
            slotProps={{
              input: { style: { fontFamily: 'monospace' } },
            }}
          />
        </Stack>
      )}
      <Typography
        variant='caption'
        color='text.secondary'
        sx={{ mt: 0.5, display: 'block' }}
      >
        {fullPath ? (
          <>
            Full prefix:{' '}
            <span style={{ fontFamily: 'monospace' }}>{fullPath}</span>
          </>
        ) : (
          'Full collection prefix: (pick an exported namespace)'
        )}
      </Typography>
    </Box>
  );
};

// OwnerSection renders the four-mode owner picker. The "existing" and
// "new" modes are server-gated on user_admin (the /users surface
// requires it); when the caller lacks that scope they're disabled and
// we surface a hint explaining why. Behaviour by mode:
//   self     — keep the calling admin as owner (no PATCH required)
//   existing — autocomplete from /users; submit transfers ownership
//              to ownerExistingUser
//   new      — inline create form; on submit POST /users first, then
//              transfer ownership. Local-only users (empty sub+issuer)
//              get an automatic password-set invite.
//   invite   — calling admin stays the owner *for now*; the form mints a
//              single-use ownership-transfer invite. On redemption the
//              recipient's account becomes the new owner (the calling
//              admin loses ownership at the same moment). Used when the
//              eventual owner isn't known up front. The recipient must
//              be able to log in to this server — existing account or
//              OIDC self-enrollment on first login.
const OwnerSection: React.FC<{
  mode: OwnerMode;
  onModeChange: (m: OwnerMode) => void;
  canManageUsers: boolean;
  me: Me | undefined;
  users: ApiUser[];
  usersLoading: boolean;
  existingUser: ApiUser | null;
  onExistingUserChange: (u: ApiUser | null) => void;
  newUserUsername: string;
  newUserDisplayName: string;
  newUserSub: string;
  newUserIssuer: string;
  onNewUserUsernameChange: (v: string) => void;
  onNewUserDisplayNameChange: (v: string) => void;
  onNewUserSubChange: (v: string) => void;
  onNewUserIssuerChange: (v: string) => void;
  newUserPaired: boolean;
  inviteSingleUse: boolean;
  onInviteSingleUseChange: (v: boolean) => void;
  // Whether the form has an enabled admin-role group row. Drives the
  // 'invite' mode's validity warning — without an admin group there's
  // nothing for the recipient to join.
  adminRowEnabled: boolean;
}> = ({
  mode,
  onModeChange,
  canManageUsers,
  me,
  users,
  usersLoading,
  existingUser,
  onExistingUserChange,
  newUserUsername,
  newUserDisplayName,
  newUserSub,
  newUserIssuer,
  onNewUserUsernameChange,
  onNewUserDisplayNameChange,
  onNewUserSubChange,
  onNewUserIssuerChange,
  newUserPaired,
  inviteSingleUse,
  onInviteSingleUseChange,
  adminRowEnabled,
}) => (
  <>
    <RadioGroup
      value={mode}
      onChange={(e) => onModeChange(e.target.value as OwnerMode)}
    >
      <FormControlLabel
        value='self'
        control={<Radio />}
        label={
          <span>
            Leave myself
            {me?.username ? (
              <>
                {' ('}
                <span style={{ fontFamily: 'monospace' }}>{me.username}</span>
                {')'}
              </>
            ) : null}{' '}
            as the owner
          </span>
        }
      />
      <FormControlLabel
        value='existing'
        control={<Radio />}
        label='Pick an existing user'
        disabled={!canManageUsers}
      />
      <FormControlLabel
        value='new'
        control={<Radio />}
        label='Create a new user'
        disabled={!canManageUsers}
      />
      <FormControlLabel
        value='invite'
        control={<Radio />}
        label='Send an ownership invite'
      />
    </RadioGroup>
    {!canManageUsers && (
      <Alert severity='info' sx={{ mt: 1 }}>
        Picking a different existing owner — or creating a new one — needs the{' '}
        <code>server.user_admin</code> scope (system admins have it; users
        granted user-admin via group also). The owner-invite option works
        without it.
      </Alert>
    )}

    {canManageUsers && mode === 'existing' && (
      <Box sx={{ mt: 2 }}>
        {/*
          Autocomplete sourced from the full /users list. We render
          "<displayName> (<username>)" with a `user-<id>` fallback for
          rows where displayName is empty. The user list is loaded on
          demand (only when this mode is selected) so a collection-admin
          who never opens the picker doesn't trigger a /users 403.
        */}
        <Autocomplete<ApiUser>
          options={users}
          loading={usersLoading}
          value={existingUser}
          onChange={(_e, value) => onExistingUserChange(value)}
          getOptionLabel={(u) =>
            u.displayName ? `${u.displayName} (${u.username})` : u.username
          }
          isOptionEqualToValue={(a, b) => a.id === b.id}
          renderInput={(params) => (
            <TextField
              {...params}
              label='Owner'
              placeholder='Search by username or display name'
              size='small'
            />
          )}
        />
      </Box>
    )}

    {canManageUsers && mode === 'new' && (
      <Box sx={{ mt: 2 }}>
        <Stack spacing={2}>
          <TextField
            label='Username'
            value={newUserUsername}
            onChange={(e) => onNewUserUsernameChange(e.target.value)}
            required
            fullWidth
            size='small'
            helperText='Machine-readable handle (used in policy strings).'
          />
          <TextField
            label='Display name (optional)'
            value={newUserDisplayName}
            onChange={(e) => onNewUserDisplayNameChange(e.target.value)}
            fullWidth
            size='small'
            helperText='Human label shown in the UI.'
          />
          {/*
            Optional OIDC pre-bind. Both must be set together (matches
            handleAddUser's rule). Leaving them empty creates a local
            user; we'll auto-mint a password-set invite for them on
            submit. Filling both attaches the row to a specific OIDC
            identity so the user's first SSO login lands here instead
            of creating a duplicate account.
          */}
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
            <TextField
              label='OIDC sub (optional)'
              value={newUserSub}
              onChange={(e) => onNewUserSubChange(e.target.value)}
              fullWidth
              size='small'
              error={!newUserPaired}
              helperText={
                newUserPaired
                  ? 'Pre-bind their IdP-issued subject claim. Leave both blank for a local-password account.'
                  : 'sub and issuer must be filled together (or both blank).'
              }
            />
            <TextField
              label='OIDC issuer (optional)'
              value={newUserIssuer}
              onChange={(e) => onNewUserIssuerChange(e.target.value)}
              fullWidth
              size='small'
              error={!newUserPaired}
              helperText={
                newUserPaired
                  ? 'Their IdP issuer URL.'
                  : 'sub and issuer must be filled together (or both blank).'
              }
            />
          </Stack>
          <Alert severity='info'>
            For local accounts (sub + issuer left blank) the form mints a
            password-set invite alongside the rest — the new user follows it
            once to choose their own password. Admins never see or set the
            password directly.
          </Alert>
        </Stack>
      </Box>
    )}

    {mode === 'invite' && (
      <Box sx={{ mt: 2 }}>
        <Typography variant='body2' color='text.secondary'>
          On link redemption, ownership transfers to the logged-in user. Hand
          them the URL out-of-band; it&apos;s shown only once at submission.
        </Typography>
      </Box>
    )}
  </>
);

const GroupRowEditor: React.FC<{
  row: GroupRow;
  onChange: (patch: Partial<GroupRow>) => void;
  // Groups the caller can see — drives the "use existing" autocomplete.
  // Loaded only when at least one row is in 'existing' mode (see the
  // SWR key in OnboardForm).
  visibleGroups: ApiGroup[];
  groupsLoading: boolean;
  // True when the caller's /groups response is unfiltered (system or
  // user-admin). Suppresses the "groups you own/administer/belong to"
  // hint, which would just be noise for someone who sees everything.
  seesAllGroups: boolean;
}> = ({ row, onChange, visibleGroups, groupsLoading, seesAllGroups }) => (
  <Box
    sx={{
      p: 2,
      border: '1px solid',
      borderColor: 'divider',
      borderRadius: 1,
      opacity: row.enabled ? 1 : 0.55,
    }}
  >
    <Box display='flex' alignItems='center' gap={2} mb={row.enabled ? 2 : 0}>
      <Switch
        checked={row.enabled}
        onChange={(e) => onChange({ enabled: e.target.checked })}
      />
      <Chip
        label={row.role === 'owner' ? 'admin' : row.role}
        color={
          row.role === 'owner'
            ? 'primary'
            : row.role === 'write'
              ? 'secondary'
              : 'default'
        }
        size='small'
        sx={{ textTransform: 'capitalize' }}
      />
      <Typography variant='body2' color='text.secondary'>
        {row.role === 'owner'
          ? 'Members can manage the collection (members, ACLs, edit) but cannot transfer ownership or delete — those stay owner-only.'
          : row.role === 'write'
            ? 'Write objects into the collection.'
            : 'List and read objects in the collection.'}
      </Typography>
    </Box>
    {row.enabled && (
      <Stack spacing={2}>
        {/*
          Source toggle: create a new group (the default) or pick an
          existing one the caller can already see. Splitting the
          per-row state on `source` keeps each branch's fields
          independent — flipping back and forth doesn't lose typed
          input, and validation only checks the fields the active
          branch actually uses.
        */}
        <RadioGroup
          row
          value={row.source}
          onChange={(e) => onChange({ source: e.target.value as GroupSource })}
        >
          <FormControlLabel
            value='create'
            control={<Radio size='small' />}
            label='Create new group'
          />
          <FormControlLabel
            value='existing'
            control={<Radio size='small' />}
            label='Use existing group'
          />
        </RadioGroup>

        {row.source === 'create' ? (
          <>
            <TextField
              label='Group name'
              value={row.name}
              onChange={(e) => {
                const v = e.target.value;
                // Clearing back to empty re-arms the auto-suggest;
                // any other edit pins the field to whatever the
                // admin typed.
                onChange({ name: v, nameDirty: v !== '' });
              }}
              required
              fullWidth
              size='small'
              helperText={
                row.nameDirty
                  ? 'Machine-readable identifier; admins use this in policy.'
                  : 'Auto-suggested from the collection name. Edit to override.'
              }
            />
            <TextField
              label='Display name (optional)'
              value={row.displayName}
              onChange={(e) => {
                const v = e.target.value;
                onChange({ displayName: v, displayNameDirty: v !== '' });
              }}
              fullWidth
              size='small'
              helperText={
                row.displayNameDirty
                  ? 'Shown in the UI; falls back to the group name when blank.'
                  : 'Auto-suggested from the collection name. Edit to override.'
              }
            />
            <TextField
              label='Description'
              value={row.description}
              onChange={(e) => onChange({ description: e.target.value })}
              fullWidth
              multiline
              rows={2}
              size='small'
            />
          </>
        ) : (
          <>
            <Autocomplete<ApiGroup>
              options={visibleGroups}
              loading={groupsLoading}
              value={row.existingGroup}
              onChange={(_e, value) => onChange({ existingGroup: value })}
              getOptionLabel={(g) =>
                g.displayName ? `${g.displayName} (${g.name})` : g.name
              }
              isOptionEqualToValue={(a, b) => a.id === b.id}
              renderInput={(params) => (
                <TextField
                  {...params}
                  label='Group'
                  placeholder='Search groups visible to you'
                  size='small'
                  required
                />
              )}
            />
            {!seesAllGroups && (
              <Typography variant='caption' color='text.secondary'>
                Choose from groups you own, administer, or belong to.
              </Typography>
            )}
          </>
        )}
      </Stack>
    )}
  </Box>
);

const ResultPanel: React.FC<{
  result: OnboardResult;
  onAnother: () => void;
  onDone: () => void;
}> = ({ result, onAnother, onDone }) => {
  const dispatch = useContext(AlertDispatchContext);
  const copy = (text: string) => {
    navigator.clipboard.writeText(text).then(() =>
      dispatch({
        type: 'openAlert',
        payload: {
          onClose: () => dispatch({ type: 'closeAlert' }),
          message: 'Copied to clipboard',
          autoHideDuration: 2000,
          alertProps: { severity: 'success' },
        },
      })
    );
  };
  return (
    <Box width='100%' maxWidth={760}>
      <Breadcrumbs aria-label='breadcrumb' sx={{ mb: 2 }}>
        <Link href='/origin/collections/'>Collections</Link>
        <Typography color='text.primary'>
          {result.partial ? 'Onboarding incomplete' : 'Onboarded'}
        </Typography>
      </Breadcrumbs>
      <Typography variant='h4' mb={result.partial ? 1 : 2}>
        {result.partial
          ? `${result.collectionName}: onboarding stopped early`
          : `${result.collectionName} is ready`}
      </Typography>
      {result.partial && (
        <Alert severity='warning' sx={{ mb: 3 }}>
          {result.partialReason ||
            'A step in the onboarding pipeline failed; the collection and any earlier groups remain in place.'}{' '}
          The sections below show what was created. You can navigate to the
          collection or the groups list to clean up partial state, then retry
          from the top.
        </Alert>
      )}

      {/*
        Show the resolved owner first — it's the question "who owns
        this now?" the admin most often asks immediately after
        onboarding. Newly-created accounts get a quick deep-link to
        the user-edit page (where the admin can also clear the
        password / look at the AUP state if needed).
      */}
      {result.owner && (
        <Paper variant='outlined' sx={{ p: 3, mb: 3 }}>
          <Typography variant='h6' mb={1}>
            Owner
          </Typography>
          <Box display='flex' alignItems='center' gap={1.5} flexWrap='wrap'>
            <Typography fontFamily='monospace'>
              {result.owner.username || '(unset)'}
            </Typography>
            {result.owner.created && (
              <Chip
                size='small'
                color='success'
                label='newly created'
                variant='outlined'
              />
            )}
            {result.owner.userId && (
              <Box ml='auto'>
                <Link
                  href={`/settings/users/edit/?id=${encodeURIComponent(result.owner.userId)}`}
                >
                  <Button size='small'>Manage user</Button>
                </Link>
              </Box>
            )}
          </Box>
        </Paper>
      )}

      <Paper variant='outlined' sx={{ p: 3, mb: 3 }}>
        <Typography variant='h6' mb={1}>
          Associated Groups
        </Typography>
        {result.groups.length === 0 ? (
          <Typography color='text.secondary'>None.</Typography>
        ) : (
          <Stack spacing={1}>
            {result.groups.map((g) => (
              <Box key={g.groupId} display='flex' alignItems='center' gap={1.5}>
                <Chip
                  label={g.role === 'owner' ? 'admin' : g.role}
                  size='small'
                  sx={{ textTransform: 'capitalize' }}
                />
                <Typography fontFamily='monospace'>{g.groupName}</Typography>
                {g.reused ? (
                  <Chip
                    size='small'
                    variant='outlined'
                    label='existing'
                    title='Re-used a group that already existed.'
                  />
                ) : (
                  <Chip
                    size='small'
                    color='success'
                    variant='outlined'
                    label='new'
                    title='Group was created during onboarding.'
                  />
                )}
                <Box ml='auto'>
                  <Link
                    href={`/groups/view/?id=${encodeURIComponent(g.groupId)}`}
                  >
                    <Button size='small'>Manage</Button>
                  </Link>
                </Box>
              </Box>
            ))}
          </Stack>
        )}
      </Paper>

      {result.ownerInviteUrl && (
        <Paper variant='outlined' sx={{ p: 3, mb: 3 }}>
          <Typography variant='h6' mb={1}>
            Ownership-transfer invite
          </Typography>
          <Alert severity='info' sx={{ mb: 2 }}>
            Hand this URL to the eventual owner. On redemption the
            collection&apos;s ownership transfers to them; you stop being the
            owner at the same moment. Single-use; shown{' '}
            <strong>only once</strong> — copy before navigating away.
          </Alert>
          <Box display='flex' alignItems='center' gap={1}>
            <TextField
              value={result.ownerInviteUrl}
              fullWidth
              size='small'
              slotProps={{
                input: {
                  readOnly: true,
                  style: { fontFamily: 'monospace', fontSize: '0.8rem' },
                },
              }}
            />
            <Tooltip title='Copy URL'>
              <IconButton onClick={() => copy(result.ownerInviteUrl)}>
                <ContentCopyIcon fontSize='small' />
              </IconButton>
            </Tooltip>
          </Box>
        </Paper>
      )}

      {/*
        Password-set invite for a freshly-minted local user. Shown only
        when the form created the user inline AND the OIDC fields were
        left blank. The token IS the credential — display once, never
        store, no re-fetch.
      */}
      {result.passwordInviteUrl && (
        <Paper variant='outlined' sx={{ p: 3, mb: 3 }}>
          <Typography variant='h6' mb={1}>
            Password setup invite
          </Typography>
          <Alert severity='warning' sx={{ mb: 2 }}>
            Hand this URL to{' '}
            <strong>{result.owner?.username ?? 'the new owner'}</strong> so they
            can choose their own password. Shown <strong>only once</strong>;
            admins never see the password.
          </Alert>
          <Box display='flex' alignItems='center' gap={1}>
            <TextField
              value={result.passwordInviteUrl}
              fullWidth
              size='small'
              slotProps={{
                input: {
                  readOnly: true,
                  style: { fontFamily: 'monospace', fontSize: '0.8rem' },
                },
              }}
            />
            <Tooltip title='Copy URL'>
              <IconButton onClick={() => copy(result.passwordInviteUrl ?? '')}>
                <ContentCopyIcon fontSize='small' />
              </IconButton>
            </Tooltip>
          </Box>
        </Paper>
      )}

      <Divider sx={{ my: 3 }} />
      <Stack direction='row' spacing={2}>
        <Button variant='contained' onClick={onDone}>
          Back to collections
        </Button>
        <Button variant='outlined' onClick={onAnother}>
          Onboard another
        </Button>
      </Stack>
    </Box>
  );
};

export default Page;
