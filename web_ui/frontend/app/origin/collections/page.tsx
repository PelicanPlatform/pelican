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

import React, { useContext, useMemo, useState } from 'react';

import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Collapse,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  FormControl,
  IconButton,
  InputLabel,
  MenuItem,
  Select,
  Skeleton,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import {
  Delete,
  Edit,
  ExpandLess,
  ExpandMore,
  Refresh,
  Share as ShareIcon,
} from '@mui/icons-material';
import Link from 'next/link';
import useSWR from 'swr';
import useApiSWR from '@/hooks/useApiSWR';
import useFuse from '@/helpers/useFuse';
import AuthenticatedContent from '@/components/layout/AuthenticatedContent';
import { AlertDispatchContext } from '@/components/AlertProvider';
import { alertOnError } from '@/helpers/util';
import { getUser } from '@/helpers/login';
import { hasScope } from '@/index';
import {
  CollectionAcl,
  CollectionSummary,
  labelForACLTarget,
} from '@/helpers/api/Collection/types';
import CollectionService from '@/helpers/api/Collection/service';
import GroupService from '@/helpers/api/Group/service';

// formatUserPill renders the canonical "Display Name (username)"
// label used elsewhere in the app. Falls back to the bare username
// when display name is unset (or matches the username), or to a
// placeholder when no card is available (deleted user, legacy row
// where ownerId never resolved). User.ID slugs are routing handles
// and never surfaced as labels here.
const formatUserPill = (
  card: CollectionSummary['ownerCard'],
  fallbackUsername: string
): string => {
  if (!card) {
    return fallbackUsername || '(unknown)';
  }
  const dn = card.displayName?.trim();
  if (!dn || dn === card.username) return card.username;
  return `${dn} (${card.username})`;
};

const Page = () => {
  const {
    data: collections,
    error,
    mutate,
  } = useApiSWR<CollectionSummary[]>(
    'Could not fetch collections',
    '/api/v1.0/origin_ui/collections',
    async () => {
      return await fetch('/api/v1.0/origin_ui/collections', { method: 'GET' });
    }
  );

  const [search, setSearch] = useState<string>('');
  const searchedData = useFuse<CollectionSummary>(collections || [], search);

  // Resolve group NAMES (the form ACL rows store) to slug IDs (the
  // /groups/view/?id=… route expects). The /groups list endpoint is
  // already filtered server-side to groups the caller can see, so
  // unknown names — e.g. an ACL granted to a group the caller has no
  // visibility into — simply stay un-linked rather than producing a
  // "permission denied" landing page.
  const { data: groups } = useSWR('groups', () => GroupService.getAll(), {
    // The collections page rarely outlives a single user action, so
    // refetching on every focus would just amplify rate-limit risk
    // without giving fresher group metadata. Manual refresh comes via
    // the existing reload button on the page.
    revalidateOnFocus: false,
  });
  const groupIdByName = useMemo(() => {
    const m = new Map<string, string>();
    for (const g of groups ?? []) {
      m.set(g.name, g.id);
    }
    return m;
  }, [groups]);

  // Mirror the backend gate on POST /origin_ui/collections: only callers
  // who hold server.collection_admin (or admin, which implies it)
  // can create. Hiding the buttons for everyone else avoids dangling
  // CTAs that would 403 the moment the user clicked them. We accept
  // EITHER role==='admin' OR the explicit scope so a system admin
  // sees the buttons regardless of how their effective scope set was
  // computed (mirrors the AuthenticatedContent gate on the form pages).
  const { data: who } = useSWR('getUser', getUser);
  const canCreate =
    who?.role === 'admin' || hasScope(who, 'server.collection_admin');
  // Mirrors the page-level gate on /settings/users/edit/: only callers
  // with server.user_admin (or admin, which implies it) can land
  // there without a 403. We use the same predicate the user-management
  // pages do so the owner pill only links to a destination the caller
  // can actually reach.
  const canEditUsers =
    who?.role === 'admin' || hasScope(who, 'server.user_admin');

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this collection?')) return;
    const resp = await fetch(`/api/v1.0/origin_ui/collections/${id}`, {
      method: 'DELETE',
    });
    if (resp.ok) {
      mutate();
    }
  };

  return (
    <AuthenticatedContent redirect={true} allowedRoles={['admin', 'user']}>
      <Box width={'100%'}>
        <Box
          mb={2}
          display={'flex'}
          justifyContent={'space-between'}
          alignItems={'center'}
        >
          <Typography variant='h4'>Collections</Typography>
          <Box display='flex' gap={1}>
            <IconButton onClick={() => mutate()}>
              <Refresh />
            </IconButton>
            {/*
              "Onboard" is the recommended path for new collections —
              one form covers collection + groups + the optional
              ownership-transfer invite. "Create" stays as a quick-add
              escape hatch (collection only; ACLs and groups handled
              separately). Both are gated on server.collection_admin
              to match the backend.
            */}
            {canCreate && (
              <>
                <Link href='/origin/collections/onboard/'>
                  <Button variant='contained' color='primary'>
                    Onboard Collection
                  </Button>
                </Link>
                <Link href='/origin/collections/create/'>
                  <Button variant='outlined'>Quick Create</Button>
                </Link>
              </>
            )}
          </Box>
        </Box>
        <Box mb={2}>
          <TextField
            size={'small'}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            label='Search'
            fullWidth
          />
        </Box>
        {error && (
          <Typography color='error'>
            Failed to load collections: {error.message}
          </Typography>
        )}
        {searchedData && searchedData.length === 0 && (
          <Typography color='text.secondary'>No collections found.</Typography>
        )}
        {(searchedData || []).map((c) => (
          <CollectionCard
            key={c.id}
            c={c}
            onDelete={() => handleDelete(c.id)}
            onChanged={() => mutate()}
            groupIdByName={groupIdByName}
            canEditUsers={canEditUsers}
          />
        ))}
      </Box>
    </AuthenticatedContent>
  );
};

// CollectionCard is a single row in the collections list. Click the
// row body to expand (or collapse) it; the Edit / Delete affordances
// stay clickable without toggling expansion. Every row always shows
// the owner pill so a user can see who runs each collection they have
// access to even when they can't edit it; the expanded body adds the
// rest of the metadata + ACL list.
// groupHrefByName resolves an ACL's group NAME (the backend
// canonicalises slug→name on write, so ACL rows carry names) to a
// `/groups/view/?id=…` URL. Returns undefined when the caller has no
// visibility into the group via /groups — we render a non-clickable
// chip in that case rather than minting a link the user can't follow.
const groupHrefByName = (
  name: string,
  groupIdByName: Map<string, string>
): string | undefined => {
  const id = groupIdByName.get(name);
  return id ? `/groups/view/?id=${encodeURIComponent(id)}` : undefined;
};

const CollectionCard: React.FC<{
  c: CollectionSummary;
  onDelete: () => void;
  onChanged: () => Promise<unknown> | void;
  groupIdByName: Map<string, string>;
  canEditUsers: boolean;
}> = ({ c, onDelete, onChanged, groupIdByName, canEditUsers }) => {
  const [open, setOpen] = useState(false);
  const [shareOpen, setShareOpen] = useState(false);
  const isShare = !!c.parentCollectionId;
  // The Create-Share button is visible on rows that the parent has
  // opted in (enableSharing) and that aren't themselves a share —
  // shares-of-shares are deliberately not supported (the token-mint
  // intersection only walks one hop). Server enforces the same gate
  // independently.
  const canCreateShare = !!c.enableSharing && !isShare;
  return (
    <Card sx={{ mb: 1 }}>
      <CardContent
        sx={{
          display: 'flex',
          alignItems: 'center',
          gap: 1,
          // Tighter "&:last-child" override — MUI's CardContent adds
          // pb=24 by default which makes a row of cards feel taller
          // than necessary.
          '&:last-child': { pb: 2 },
          cursor: 'pointer',
          '&:hover': { backgroundColor: 'action.hover' },
        }}
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        role='button'
      >
        <Box flexGrow={1} minWidth={0}>
          <Box display='flex' alignItems='center' gap={1} flexWrap='wrap'>
            <Typography variant='h6' sx={{ wordBreak: 'break-all' }}>
              {c.name}
            </Typography>
            <Chip
              label={c.visibility}
              size='small'
              color={c.visibility === 'public' ? 'success' : 'default'}
            />
            {/*
              Annotate share rows so they're distinguishable in the
              listing — per the design we don't break shares out into
              a separate page, just mark them inline. The chip is
              non-clickable; the parent collection ID is surfaced in
              the expanded panel below.
            */}
            {isShare && (
              <Tooltip
                title={`Share of collection ${c.parentCollectionId}`}
                placement='top'
              >
                <Chip
                  size='small'
                  label='share'
                  variant='outlined'
                  icon={<ShareIcon fontSize='small' />}
                />
              </Tooltip>
            )}
          </Box>
          {/*
            Namespace is the path operators reach this collection at —
            arguably the most useful identifier on the row, so it sits
            immediately under the name in monospace rather than being
            buried in the expanded panel.
          */}
          <Typography
            variant='body2'
            mt={0.25}
            sx={{
              fontFamily: 'monospace',
              wordBreak: 'break-all',
              color: 'text.secondary',
            }}
          >
            {c.namespace}
          </Typography>
          <Box
            display='flex'
            alignItems='center'
            gap={1}
            mt={0.5}
            flexWrap='wrap'
          >
            <Typography variant='caption' color='text.secondary'>
              Owner:
            </Typography>
            <Tooltip
              title={c.ownerCard?.id ? `User.ID: ${c.ownerCard.id}` : ''}
              placement='top'
            >
              {/*
                Owner pill links to the user's edit page when the
                caller holds server.user_admin (the gate on
                /settings/users/edit/) AND we have an ownerCard ID to
                route by. Non-admin callers see the same chip without
                navigation — preventing dead links into a page that
                would just 403.
              */}
              {canEditUsers && c.ownerCard?.id ? (
                <Link
                  href={`/settings/users/edit/?id=${encodeURIComponent(c.ownerCard.id)}`}
                  // The card body has its own onClick (toggle expand);
                  // stop propagation so a click on the pill navigates
                  // instead of also collapsing/expanding the row.
                  onClick={(e) => e.stopPropagation()}
                >
                  <Chip
                    size='small'
                    variant='outlined'
                    label={formatUserPill(c.ownerCard, c.owner)}
                    clickable
                  />
                </Link>
              ) : (
                <Chip
                  size='small'
                  variant='outlined'
                  label={formatUserPill(c.ownerCard, c.owner)}
                />
              )}
            </Tooltip>
            {c.adminCard && (
              <>
                <Typography variant='caption' color='text.secondary'>
                  · Admin group:
                </Typography>
                <Link
                  href={`/groups/view/?id=${encodeURIComponent(c.adminCard.id)}`}
                  // The card body has its own onClick (toggle expand);
                  // stop propagation so a click on the pill navigates
                  // instead of also collapsing/expanding the row.
                  onClick={(e) => e.stopPropagation()}
                >
                  <Chip
                    size='small'
                    variant='outlined'
                    color='primary'
                    label={c.adminCard.name}
                    clickable
                  />
                </Link>
              </>
            )}
          </Box>
        </Box>
        <Box
          display='flex'
          gap={0.5}
          // Stop the row's onClick from firing when the user actually
          // wants to edit / delete. Each affordance keeps its own
          // navigation / confirm flow.
          onClick={(e) => e.stopPropagation()}
        >
          {/*
            Render the pencil only on rows the caller can actually
            modify. The backend computes canEdit (owner, admin-group
            member, collection_admin / admin) per row and surfaces
            it on ListCollectionRes; older payloads without the field
            are treated as not-editable to avoid silently re-enabling
            the affordance during a partial deploy.
          */}
          {c.canEdit && (
            <Link
              href={`/origin/collections/edit/?id=${encodeURIComponent(c.id)}`}
            >
              <IconButton title='Edit collection'>
                <Edit />
              </IconButton>
            </Link>
          )}
          {/*
            Create-share affordance. Only visible when the collection's
            owner has opted in to user-driven shares (c.enableSharing)
            and this row isn't itself a share. The actual permission
            (read access on the parent) is enforced server-side; this
            UI gate just hides a button that would always 409.
          */}
          {canCreateShare && (
            <IconButton title='Create share' onClick={() => setShareOpen(true)}>
              <ShareIcon />
            </IconButton>
          )}
          <IconButton
            color='error'
            onClick={onDelete}
            title='Delete collection'
          >
            <Delete />
          </IconButton>
          <Tooltip title={open ? 'Hide details' : 'Show details'}>
            <IconButton
              size='small'
              aria-label={open ? 'Collapse row' : 'Expand row'}
            >
              {open ? <ExpandLess /> : <ExpandMore />}
            </IconButton>
          </Tooltip>
        </Box>
      </CardContent>
      <Collapse in={open} unmountOnExit>
        <Divider />
        <ExpandedDetails c={c} open={open} groupIdByName={groupIdByName} />
      </Collapse>
      {canCreateShare && (
        <CreateShareDialog
          open={shareOpen}
          parent={c}
          onClose={() => setShareOpen(false)}
          onCreated={async () => {
            setShareOpen(false);
            await onChanged();
          }}
        />
      )}
    </Card>
  );
};

// ExpandedDetails lazy-loads the per-collection ACL list the first
// time the row is expanded (mounting under <Collapse unmountOnExit>
// guarantees the SWR fetch only fires when the body becomes visible).
// All other fields are already in the list response.
const ExpandedDetails: React.FC<{
  c: CollectionSummary;
  open: boolean;
  groupIdByName: Map<string, string>;
}> = ({ c, groupIdByName }) => {
  const { data: acls, isLoading } = useSWR<CollectionAcl[] | undefined>(
    `collection/${c.id}/acls`,
    () => CollectionService.listAcls(c.id)
  );

  return (
    <Box sx={{ p: 2, backgroundColor: 'action.hover' }}>
      <Stack spacing={1.5}>
        {c.description && (
          <Section label='Description'>
            <Typography variant='body2'>{c.description}</Typography>
          </Section>
        )}
        <Section label='Access groups'>
          {isLoading ? (
            <Skeleton variant='rounded' height={36} />
          ) : !acls || acls.length === 0 ? (
            <Typography variant='body2' color='text.secondary'>
              No read or write groups attached.
            </Typography>
          ) : (
            <Box display='flex' gap={1} flexWrap='wrap'>
              {acls.map((acl) => {
                // ACL rows store the group NAME (the backend
                // canonicalises slug→name on write); resolve to the
                // slug ID via groupIdByName so the chip links to
                // /groups/view/?id=…. When the caller can't see this
                // group in /groups (no membership / admin / owner)
                // — or when the row targets the all-authenticated
                // sentinel, which isn't a real group at all — the
                // lookup misses and we render a non-clickable chip.
                const href = groupHrefByName(acl.groupId, groupIdByName);
                const label = `${acl.role}: ${labelForACLTarget(acl.groupId)}`;
                const chip = (
                  <Chip
                    size='small'
                    label={label}
                    color={
                      acl.role === 'write'
                        ? 'secondary'
                        : acl.role === 'owner'
                          ? 'default'
                          : 'primary'
                    }
                    variant={acl.role === 'owner' ? 'outlined' : 'filled'}
                    clickable={!!href}
                  />
                );
                return (
                  <React.Fragment key={`${acl.groupId}:${acl.role}`}>
                    {href ? <Link href={href}>{chip}</Link> : chip}
                  </React.Fragment>
                );
              })}
            </Box>
          )}
        </Section>
        {(c.createdAt || c.updatedAt) && (
          <Section label='Timestamps'>
            <Typography variant='caption' color='text.secondary'>
              {c.createdAt &&
                `Created ${new Date(c.createdAt).toLocaleString()}`}
              {c.createdAt && c.updatedAt && ' · '}
              {c.updatedAt &&
                `Updated ${new Date(c.updatedAt).toLocaleString()}`}
            </Typography>
          </Section>
        )}
      </Stack>
    </Box>
  );
};

const Section: React.FC<{ label: string; children: React.ReactNode }> = ({
  label,
  children,
}) => (
  <Box>
    <Typography variant='caption' color='text.secondary'>
      {label}
    </Typography>
    <Box mt={0.25}>{children}</Box>
  </Box>
);

// CreateShareDialog mints a child collection ("share") whose
// parent_collection_id is the supplied parent's. Per the design
// (docs/collections-design.md), self-service share creation needs
// only Collection_Read on the parent — the heavy lifting (clamping
// the recipient's tokens by the share owner's CURRENT parent
// access) lives in the OA4MP scope-emission path.
//
// The dialog deliberately stays minimal: name, description,
// namespace (defaults to the parent's), visibility (defaults to
// private). The new share's owner is the calling user; recipients
// are added later via ACL grants on the share's edit page (the
// same surface used by regular collection ACLs).
const CreateShareDialog: React.FC<{
  open: boolean;
  parent: CollectionSummary;
  onClose: () => void;
  onCreated: () => Promise<unknown> | void;
}> = ({ open, parent, onClose, onCreated }) => {
  const dispatch = useContext(AlertDispatchContext);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [namespace, setNamespace] = useState('');
  const [visibility, setVisibility] = useState<'private' | 'public'>('private');
  const [busy, setBusy] = useState(false);
  // Reset state every time the dialog opens — without this, a user who
  // closes the dialog and re-opens it would see stale fields from the
  // last attempt.
  React.useEffect(() => {
    if (open) {
      setName('');
      setDescription('');
      setNamespace('');
      setVisibility('private');
    }
  }, [open]);

  const submit = async () => {
    if (!name) return;
    setBusy(true);
    try {
      const ok = await alertOnError(
        async () => {
          const r = await fetch(
            `/api/v1.0/origin_ui/collections/${encodeURIComponent(parent.id)}/shares`,
            {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                name,
                description,
                // Server defaults the namespace to the parent's when
                // empty, and rejects anything outside the parent's
                // sub-tree. Pass through whatever the user typed.
                namespace,
                visibility,
              }),
            }
          );
          if (!r.ok) {
            const text = await r.text();
            throw new Error(text || `share create failed (${r.status})`);
          }
          return true;
        },
        'Failed to create share',
        dispatch
      );
      if (ok) {
        await onCreated();
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth='sm' fullWidth>
      <DialogTitle>Create share of {parent.name}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <Alert severity='info'>
            A share is a child collection that delegates a subset of{' '}
            <strong>{parent.name}</strong>&apos;s access to whoever you grant
            ACLs to. Access is impersonated as you, the share owner, and is
            automatically clamped to whatever access you currently hold on{' '}
            {parent.name}.
          </Alert>
          <TextField
            label='Share name'
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
            fullWidth
            autoFocus
          />
          <TextField
            label='Description'
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            fullWidth
            multiline
            rows={2}
          />
          <TextField
            label='Namespace (optional)'
            value={namespace}
            onChange={(e) => setNamespace(e.target.value)}
            placeholder={parent.namespace}
            helperText={`Defaults to ${parent.namespace}. Must equal or be a path-descendant of the parent's namespace.`}
            fullWidth
            slotProps={{
              input: {
                style: { fontFamily: 'monospace' },
              },
            }}
          />
          <FormControl fullWidth>
            <InputLabel>Visibility</InputLabel>
            <Select
              value={visibility}
              label='Visibility'
              onChange={(e) =>
                setVisibility(e.target.value as 'private' | 'public')
              }
            >
              <MenuItem value='private'>Private</MenuItem>
              <MenuItem value='public'>Public</MenuItem>
            </Select>
          </FormControl>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={busy}>
          Cancel
        </Button>
        <Button variant='contained' onClick={submit} disabled={busy || !name}>
          {busy ? 'Creating…' : 'Create share'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default Page;
