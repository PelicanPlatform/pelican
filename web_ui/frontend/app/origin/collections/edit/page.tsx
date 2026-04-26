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

// Edit page for an existing collection. Mirrors the ownership model
// the user/group-design rewrite brought in:
//
//   * Owner: a single user, transferable.
//   * Admin group: an OPTIONAL group whose members can manage the
//     collection day-to-day (members, ACLs, name/description/visibility).
//     They CANNOT transfer ownership or delete the collection — those
//     stay owner-exclusive so an admin-group member can't seize or
//     destroy the collection out from under the rightful owner.
//   * Read / Write groups: ACL rows, listed and editable here.
//
// The page is the authoritative read/edit surface for those four
// fields plus the basic collection metadata. Anything orthogonal
// (members, metadata) lives elsewhere.

import React, {
  Suspense,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';
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
  Select,
  Skeleton,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import DeleteIcon from '@mui/icons-material/Delete';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import useSWR from 'swr';

import AuthenticatedContent from '@/components/layout/AuthenticatedContent';
import { AlertDispatchContext } from '@/components/AlertProvider';
import { alertOnError } from '@/helpers/util';
import {
  CollectionAcl,
  CollectionService,
  CollectionVisibility,
  GroupService,
  UserService,
} from '@/helpers/api';
import { Group } from '@/helpers/api/Group/types';
import { getUser } from '@/helpers/login';
import { hasScope } from '@/index';

// Slim UserCard shape — what /users/:id/candidate-owners returns and
// what /users returns (modulo extra fields the picker doesn't read).
// Defined locally so the edit page doesn't take on the full User
// type's contract.
interface UserOption {
  id: string;
  username: string;
  displayName: string;
}

// formatUserPill renders the canonical "Display Name (username)"
// label used elsewhere in the app. Falls back to the bare username
// when the user has no display name set, and to the User.ID when no
// username is known (defensive — should not happen for live rows).
const formatUserPill = (
  user: Pick<UserOption, 'username' | 'displayName'> | undefined,
  fallbackId: string
): string => {
  if (!user) return fallbackId;
  const name = user.displayName?.trim();
  if (!name || name === user.username) return user.username;
  return `${name} (${user.username})`;
};

const Page = () => (
  // The backend's PATCH /collections/:id permits the row's owner,
  // admin-group members, AND server.collection_admin / web_admin
  // holders. Gating on collection_admin alone here would lock out an
  // ordinary owner trying to edit *their own* collection — the
  // permission depends on the row, which we can't know at gate time.
  // So the page-level check is just "logged in"; the load + save
  // calls return the actual authoritative answer (404 if the caller
  // can't see the row, 403 on save if they can read but not modify).
  <AuthenticatedContent redirect={true}>
    <Suspense fallback={<Skeleton variant='rounded' height={400} />}>
      <EditPage />
    </Suspense>
  </AuthenticatedContent>
);

const EditPage = () => {
  const params = useSearchParams();
  const collectionID = params.get('id') ?? '';
  if (!collectionID) {
    return <Alert severity='error'>Missing ?id= in URL</Alert>;
  }
  return <EditForm collectionID={collectionID} />;
};

const EditForm: React.FC<{ collectionID: string }> = ({ collectionID }) => {
  const dispatch = useContext(AlertDispatchContext);

  const {
    data: collection,
    isLoading: collectionLoading,
    mutate: mutateCollection,
  } = useSWR(`collection/${collectionID}`, () =>
    alertOnError(
      () => CollectionService.getOne(collectionID),
      'Failed to load collection',
      dispatch
    )
  );

  const {
    data: acls,
    isLoading: aclsLoading,
    mutate: mutateAcls,
  } = useSWR<CollectionAcl[] | undefined>(
    `collection/${collectionID}/acls`,
    () =>
      alertOnError(
        () => CollectionService.listAcls(collectionID),
        'Failed to load ACLs',
        dispatch
      )
  );

  // All groups on the server, used to populate the admin-group picker
  // and the read/write ACL pickers. Cached with SWR so opening the
  // edit page repeatedly is cheap.
  const { data: groups } = useSWR<Group[] | undefined>('groups', () =>
    alertOnError(GroupService.getAll, 'Failed to load groups', dispatch)
  );

  // Caller's identity + scopes — drives which "owner candidates"
  // source we hit. user_admin can see every user; everyone else
  // gets the collection-scoped candidate list (current owner +
  // admin-group members + ACL-group members).
  const { data: who } = useSWR('getUser', getUser);
  const canListAllUsers = hasScope(who, 'server.user_admin');

  // Owner pickers: branch on canListAllUsers. Both keys are scoped
  // by the caller's privilege so SWR caches the right list and
  // doesn't leak the global list into a non-user-admin's session.
  // The full /users response carries extra fields the picker
  // doesn't read; project to UserOption shape so both branches
  // produce the same array type.
  const { data: allUsers } = useSWR<UserOption[] | undefined>(
    canListAllUsers ? 'users-for-owner-picker' : null,
    async () => {
      const rows = await alertOnError(
        UserService.getAll,
        'Failed to load users',
        dispatch
      );
      return rows?.map((u) => ({
        id: u.id,
        username: u.username,
        displayName: u.displayName ?? '',
      }));
    }
  );
  const { data: candidateOwners } = useSWR<UserOption[] | undefined>(
    !canListAllUsers ? `collection/${collectionID}/candidate-owners` : null,
    () =>
      alertOnError(
        () => CollectionService.candidateOwners(collectionID),
        'Failed to load candidate owners',
        dispatch
      )
  );
  const ownerOptions: UserOption[] = useMemo(() => {
    const src = canListAllUsers ? allUsers : candidateOwners;
    return src ?? [];
  }, [canListAllUsers, allUsers, candidateOwners]);

  // Local form state — initialised from the loaded collection on
  // first render and reset when the upstream record changes.
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [visibility, setVisibility] = useState<CollectionVisibility>('private');
  const [ownerID, setOwnerID] = useState('');
  const [adminGroupID, setAdminGroupID] = useState<string>('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!collection) return;
    setName(collection.name);
    setDescription(collection.description ?? '');
    setVisibility(collection.visibility);
    setOwnerID(collection.ownerId ?? '');
    setAdminGroupID(collection.adminId ?? '');
  }, [collection]);

  // Resolve the admin-group ID to a friendly label for the chip in
  // the picker.
  const adminGroup = useMemo<Group | undefined>(
    () => groups?.find((g) => g.id === adminGroupID),
    [groups, adminGroupID]
  );

  const dirty = useMemo(() => {
    if (!collection) return false;
    return (
      name !== collection.name ||
      description !== (collection.description ?? '') ||
      visibility !== collection.visibility ||
      ownerID !== (collection.ownerId ?? '') ||
      adminGroupID !== (collection.adminId ?? '')
    );
  }, [collection, name, description, visibility, ownerID, adminGroupID]);

  const save = async () => {
    if (!collection) return;
    setSaving(true);
    const ok = await alertOnError(
      () =>
        CollectionService.update(collection.id, {
          name: name !== collection.name ? name : undefined,
          description:
            description !== (collection.description ?? '')
              ? description
              : undefined,
          visibility:
            visibility !== collection.visibility ? visibility : undefined,
          ownerId: ownerID !== (collection.ownerId ?? '') ? ownerID : undefined,
          adminId:
            adminGroupID !== (collection.adminId ?? '')
              ? adminGroupID
              : undefined,
        }).then(() => true),
      'Failed to save collection',
      dispatch
    );
    setSaving(false);
    if (ok) {
      dispatch({
        type: 'openAlert',
        payload: {
          onClose: () => dispatch({ type: 'closeAlert' }),
          message: 'Collection updated',
          autoHideDuration: 3000,
          alertProps: { severity: 'success' },
        },
      });
      await mutateCollection();
    }
  };

  if (collectionLoading || !collection) {
    return <Skeleton variant='rounded' height={500} />;
  }

  return (
    <Box width='100%' maxWidth={760}>
      <Breadcrumbs aria-label='breadcrumb' sx={{ mb: 2 }}>
        <Link href='/origin/collections/'>Collections</Link>
        <Typography color='text.primary'>{collection.name}</Typography>
      </Breadcrumbs>
      <Typography variant='h4' mb={1}>
        Edit collection
      </Typography>
      <Typography
        variant='caption'
        color='text.secondary'
        mb={3}
        display='block'
      >
        <code>{collection.namespace}</code> · created{' '}
        {collection.createdAt
          ? new Date(collection.createdAt).toLocaleDateString()
          : 'unknown'}
      </Typography>

      {/* --- Basic metadata --- */}
      <Paper variant='outlined' sx={{ p: 3, mb: 3 }}>
        <Typography variant='h6' mb={2}>
          Details
        </Typography>
        <TextField
          label='Name'
          value={name}
          onChange={(e) => setName(e.target.value)}
          fullWidth
          sx={{ mb: 2 }}
          required
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

      {/* --- Ownership --- */}
      <Paper variant='outlined' sx={{ p: 3, mb: 3 }}>
        <Typography variant='h6' mb={1}>
          Ownership
        </Typography>
        <Typography variant='body2' color='text.secondary' mb={2}>
          One user owns the collection. Setting the admin group (optional) lets
          its members manage the collection day-to-day — members, ACLs, and the
          collection's metadata. Transferring ownership and deleting the
          collection stay owner-only.
        </Typography>
        {/*
          Owner picker. The dropdown source depends on the caller's
          privilege:
            * server.user_admin → every user on the server (so the
              admin can transfer ownership to anyone, including
              users who aren't yet related to the collection).
            * Otherwise → the candidate-owners list from the
              collection itself: current owner + admin-group members
              + ACL-group members. This keeps the picker useful for
              a project-owner who can re-assign within their team
              without leaking the global users list.
          The displayed label is always "Display Name (username)" —
          User.ID slugs are routing handles and never appear in the
          UI.
        */}
        <Autocomplete
          options={ownerOptions}
          value={ownerOptions.find((u) => u.id === ownerID) ?? undefined}
          // disableClearable: every collection must always have an
          // owner; the backend rejects an empty PATCH but the form
          // shouldn't even let the admin try. To hand the
          // collection off to a future user, use the
          // "Transfer via invite link" section below.
          disableClearable
          onChange={(_, v) => {
            if (v) setOwnerID(v.id);
          }}
          getOptionLabel={(u) =>
            formatUserPill(
              { username: u.username, displayName: u.displayName },
              u.id
            )
          }
          isOptionEqualToValue={(a, b) => a.id === b.id}
          renderInput={(params) => (
            <TextField
              {...params}
              label='Owner'
              helperText={
                canListAllUsers
                  ? 'Pick any user on the server. The owner has full management authority.'
                  : 'Pick from the collection’s admin group / ACL members. Ask a user-admin to transfer to anyone outside that set.'
              }
            />
          )}
          renderOption={(props, u) => {
            const { key, ...rest } =
              props as React.HTMLAttributes<HTMLLIElement> & {
                key?: React.Key;
              };
            const label = formatUserPill(
              { username: u.username, displayName: u.displayName },
              u.id
            );
            const showSubLine = u.displayName && u.displayName !== u.username;
            return (
              <li key={key} {...rest}>
                <Box>
                  <Typography variant='body2'>{label}</Typography>
                  {showSubLine && (
                    <Typography
                      variant='caption'
                      color='text.secondary'
                      sx={{ fontFamily: 'monospace' }}
                    >
                      {u.username}
                    </Typography>
                  )}
                </Box>
              </li>
            );
          }}
          sx={{ mb: 2 }}
        />
        <Autocomplete
          options={groups ?? []}
          value={adminGroup ?? null}
          onChange={(_, v) => setAdminGroupID(v?.id ?? '')}
          getOptionLabel={(g) => g.displayName || g.name}
          isOptionEqualToValue={(a, b) => a.id === b.id}
          renderInput={(params) => (
            <TextField
              {...params}
              label='Admin group (optional)'
              helperText='Members can manage members, ACLs, and the collection’s metadata. Cannot transfer ownership or delete the collection — those stay owner-only. Clear to remove the admin group.'
            />
          )}
          renderOption={(props, g) => {
            const { key, ...rest } =
              props as React.HTMLAttributes<HTMLLIElement> & {
                key?: React.Key;
              };
            return (
              <li key={key} {...rest}>
                <Box>
                  <Typography variant='body2'>
                    {g.displayName || g.name}
                  </Typography>
                  {g.displayName && g.displayName !== g.name && (
                    <Typography
                      variant='caption'
                      color='text.secondary'
                      sx={{ fontFamily: 'monospace' }}
                    >
                      {g.name}
                    </Typography>
                  )}
                </Box>
              </li>
            );
          }}
        />
        <TransferViaInvite collectionID={collectionID} />
      </Paper>

      {/* --- Read / Write group ACLs --- */}
      <AclSection
        collectionID={collectionID}
        acls={acls ?? []}
        loading={aclsLoading}
        groups={groups ?? []}
        onChanged={mutateAcls}
      />

      <Stack direction='row' spacing={2} mt={3}>
        <Button variant='contained' onClick={save} disabled={!dirty || saving}>
          {saving ? 'Saving...' : 'Save changes'}
        </Button>
        <Link href='/origin/collections/'>
          <Button variant='outlined'>Back to collections</Button>
        </Link>
      </Stack>
    </Box>
  );
};

// TransferViaInvite mints a single-use ownership-transfer invite for
// the collection. Useful when the eventual owner doesn't exist yet,
// or doesn't want to be onboarded by ID — the admin hands them the
// URL out-of-band; on redemption, ownership transfers atomically and
// the original owner loses ownership at the same moment.
//
// Server-side gate is owner-or-collection-admin, mirroring the direct
// PATCH ownerId path (admin-group members cannot mint these — that
// would let them seize the collection just as easily as a direct
// transfer would have). When a non-owner clicks "Generate," the call
// returns 404 and the inline error explains why.
const TransferViaInvite: React.FC<{ collectionID: string }> = ({
  collectionID,
}) => {
  const dispatch = useContext(AlertDispatchContext);
  const [busy, setBusy] = useState(false);
  const [link, setLink] = useState<string | null>(null);

  const generate = async () => {
    setBusy(true);
    const res = await alertOnError(
      () =>
        CollectionService.createOwnershipInvite(collectionID, {
          expiresIn: '168h', // 7 days, matching the group-invite default
        }),
      'Failed to create ownership-transfer invite',
      dispatch
    );
    setBusy(false);
    if (res?.inviteToken) {
      const url =
        typeof window === 'undefined'
          ? `/view/invite/redeem?token=${encodeURIComponent(res.inviteToken)}`
          : `${window.location.origin}/view/invite/redeem?token=${encodeURIComponent(res.inviteToken)}`;
      setLink(url);
    }
  };

  return (
    <Box mt={3}>
      <Divider sx={{ mb: 2 }} />
      <Typography variant='subtitle1' mb={1}>
        Transfer via invite link
      </Typography>
      <Typography variant='body2' color='text.secondary' mb={2}>
        Mint a single-use link that, when redeemed by an authenticated user,
        makes them the new owner. The current owner loses ownership at the same
        moment. Useful when the recipient doesn&apos;t have an account yet
        (they&apos;ll self-enroll via OIDC on first login) or to avoid having to
        type someone&apos;s User.ID into the picker above. Only the owner can
        mint these.
      </Typography>
      {link ? (
        <Stack spacing={1}>
          <Alert severity='success'>
            Link minted — copy it now. It is shown <strong>once</strong> and
            expires in 7 days.
          </Alert>
          <TextField
            value={link}
            fullWidth
            size='small'
            slotProps={{
              input: {
                readOnly: true,
                style: { fontFamily: 'monospace', fontSize: '0.8rem' },
              },
            }}
          />
          <Box display='flex' gap={1}>
            <Button
              size='small'
              variant='outlined'
              onClick={() => navigator.clipboard.writeText(link)}
            >
              Copy URL
            </Button>
            <Button size='small' onClick={() => setLink(null)}>
              Done
            </Button>
          </Box>
        </Stack>
      ) : (
        <Button variant='outlined' onClick={generate} disabled={busy}>
          {busy ? 'Generating…' : 'Generate transfer link'}
        </Button>
      )}
    </Box>
  );
};

const AclSection: React.FC<{
  collectionID: string;
  acls: CollectionAcl[];
  loading: boolean;
  groups: Group[];
  onChanged: () => Promise<CollectionAcl[] | undefined> | void;
}> = ({ collectionID, acls, loading, groups, onChanged }) => {
  const dispatch = useContext(AlertDispatchContext);

  // Read/write are the only roles new grants accept; AclRoleOwner
  // legacy rows are listed for the admin to clean up but no longer
  // appear in the role picker (the role's authority moved onto
  // Collection.AdminID).
  const [pickerGroup, setPickerGroup] = useState<Group | null>(null);
  const [pickerRole, setPickerRole] = useState<'read' | 'write'>('read');
  const [granting, setGranting] = useState(false);
  const [revokingKey, setRevokingKey] = useState<string | null>(null);

  const grant = async () => {
    if (!pickerGroup) return;
    setGranting(true);
    const ok = await alertOnError(
      () =>
        CollectionService.grantAcl(collectionID, {
          groupId: pickerGroup.name,
          role: pickerRole,
        }).then(() => true),
      `Failed to grant ${pickerRole} to "${pickerGroup.name}"`,
      dispatch
    );
    setGranting(false);
    if (ok) {
      setPickerGroup(null);
      await onChanged();
    }
  };

  const revoke = async (acl: CollectionAcl) => {
    const key = `${acl.groupId}:${acl.role}`;
    setRevokingKey(key);
    const ok = await alertOnError(
      () =>
        CollectionService.revokeAcl(collectionID, {
          groupId: acl.groupId,
          role: acl.role,
        }).then(() => true),
      `Failed to revoke ${acl.role} from "${acl.groupId}"`,
      dispatch
    );
    setRevokingKey(null);
    if (ok) await onChanged();
  };

  return (
    <Paper variant='outlined' sx={{ p: 3, mb: 3 }}>
      <Typography variant='h6' mb={1}>
        Access groups
      </Typography>
      <Typography variant='body2' color='text.secondary' mb={2}>
        Read groups can list members and read content. Write groups can also add
        and remove members. For full management authority, set the admin group
        above instead.
      </Typography>
      {loading ? (
        <Skeleton variant='rounded' height={80} />
      ) : acls.length === 0 ? (
        <Typography variant='body2' color='text.secondary' mb={2}>
          No read or write groups attached yet.
        </Typography>
      ) : (
        <Stack divider={<Divider />} mb={2}>
          {acls.map((acl) => {
            const key = `${acl.groupId}:${acl.role}`;
            const legacy = acl.role === 'owner';
            return (
              <Box key={key} display='flex' alignItems='center' gap={2} py={1}>
                <Chip
                  label={acl.role}
                  size='small'
                  color={
                    legacy
                      ? 'default'
                      : acl.role === 'write'
                        ? 'secondary'
                        : 'primary'
                  }
                  variant={legacy ? 'outlined' : 'filled'}
                  sx={{ textTransform: 'capitalize' }}
                />
                <Typography sx={{ fontFamily: 'monospace' }}>
                  {acl.groupId}
                </Typography>
                {legacy && (
                  <Tooltip title='Legacy owner-role ACL. Ownership now lives on the Collection.OwnerID and AdminID fields; safe to revoke this row once the new fields are populated.'>
                    <Chip label='legacy' size='small' variant='outlined' />
                  </Tooltip>
                )}
                <Box ml='auto'>
                  <IconButton
                    size='small'
                    color='warning'
                    onClick={() => revoke(acl)}
                    disabled={revokingKey === key}
                    aria-label={`Revoke ${acl.role} from ${acl.groupId}`}
                  >
                    <DeleteIcon fontSize='small' />
                  </IconButton>
                </Box>
              </Box>
            );
          })}
        </Stack>
      )}

      {/* Grant a new ACL. */}
      <Stack direction='row' spacing={1} alignItems='flex-start'>
        <Autocomplete
          sx={{ flex: 1 }}
          options={groups}
          value={pickerGroup}
          onChange={(_, v) => setPickerGroup(v)}
          getOptionLabel={(g) => g.displayName || g.name}
          isOptionEqualToValue={(a, b) => a.id === b.id}
          renderInput={(params) => (
            <TextField {...params} label='Add group' size='small' />
          )}
        />
        <FormControl size='small' sx={{ minWidth: 120 }}>
          <InputLabel>Role</InputLabel>
          <Select
            value={pickerRole}
            label='Role'
            onChange={(e) => setPickerRole(e.target.value as 'read' | 'write')}
          >
            <MenuItem value='read'>Read</MenuItem>
            <MenuItem value='write'>Write</MenuItem>
          </Select>
        </FormControl>
        <Button
          variant='contained'
          onClick={grant}
          disabled={!pickerGroup || granting}
        >
          {granting ? 'Adding...' : 'Add'}
        </Button>
      </Stack>
    </Paper>
  );
};

export default Page;
