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

// Owned collections: a unified, origin-scoped view of "collections I
// own" with the groups attached to each, so the owner of a project
// doesn't have to bounce between /origin/collections/ (filtered to
// their rows by hand) and /groups/ (to see who they delegated
// management to). Per ticket #3298 the data is already there —
// /origin_ui/collections returns owner identity, and
// /origin_ui/collections/:id/acl returns the wired-up groups by
// name. This page is a join of those two endpoints, scoped
// client-side to rows whose `owner` matches the calling user.
//
// Lives at /origin/owned/ rather than the previous /faculty/ — the
// name is descriptive (it shows what you OWN), origin-specific (the
// data is per-origin), and avoids the institution-specific term
// "faculty" that the original sketch used.

import React, { useContext, useMemo } from 'react';
import {
  Alert,
  Box,
  Breadcrumbs,
  Button,
  Card,
  CardActions,
  CardContent,
  Chip,
  Divider,
  Skeleton,
  Stack,
  Typography,
} from '@mui/material';
import Link from 'next/link';
import useSWR from 'swr';

import AuthenticatedContent from '@/components/layout/AuthenticatedContent';
import { AlertDispatchContext } from '@/components/AlertProvider';
import { alertOnError } from '@/helpers/util';
import {
  CollectionAcl,
  CollectionAclRole,
  CollectionService,
  CollectionSummary,
  GroupService,
  Me,
  MeService,
} from '@/helpers/api';
// Use the API package's Group type (the one GroupService.getAll
// returns), not the global types.ts copy. The two have drifted in
// minor ways (member-row shape) and useSWR's generic inference picks
// the wrong overload when the fetcher's return type doesn't line up
// exactly with the SWR data type.
import type { Group } from '@/helpers/api/Group';

const Page = () => (
  <AuthenticatedContent redirect={true} allowedRoles={['admin', 'user']}>
    <OwnedCollectionsHome />
  </AuthenticatedContent>
);

const OwnedCollectionsHome: React.FC = () => {
  const dispatch = useContext(AlertDispatchContext);

  // The three foundational fetches: who am I, what collections can I
  // see, what groups exist server-wide. SWR keys are stable strings so
  // navigations back to this page reuse the cache.
  const { data: me, isLoading: meLoading } = useSWR<Me | undefined>('me', () =>
    alertOnError(MeService.get, 'Failed to load your account', dispatch)
  );

  const { data: allCollections, isLoading: collectionsLoading } = useSWR<
    CollectionSummary[] | undefined
  >('origin/collections', () =>
    alertOnError(CollectionService.list, 'Failed to load collections', dispatch)
  );

  // GroupService.getAll returns the groups the caller can see. We use
  // it as a name->record index when resolving ACL groupIds (which are
  // group *names*, see the comment in CollectionAcl). If a referenced
  // group isn't visible to the caller, we still surface the bare name
  // — this page is a read-only summary, not an authz boundary.
  const { data: allGroups, isLoading: groupsLoading } = useSWR<
    Group[] | undefined
  >('groups:all', () =>
    alertOnError(GroupService.getAll, 'Failed to load groups', dispatch)
  );

  // Filter to collections this user owns. The backend stamps the
  // creator's username onto Collection.owner at create time; comparing
  // to me.username matches that wire shape.
  const ownedCollections = useMemo(() => {
    if (!me || !allCollections) return undefined;
    return allCollections.filter((c) => c.owner === me.username);
  }, [me, allCollections]);

  if (meLoading || collectionsLoading || groupsLoading || !me) {
    return (
      <Box width='100%' maxWidth={960}>
        <Header />
        <Stack spacing={2}>
          <Skeleton variant='rounded' height={120} />
          <Skeleton variant='rounded' height={120} />
        </Stack>
      </Box>
    );
  }

  return (
    <Box width='100%' maxWidth={960}>
      <Header />
      <Alert severity='info' sx={{ mb: 2 }}>
        Showing collections owned by <strong>{me.username}</strong>. Collections
        with other owners (or that you only have read or write access to) are
        not listed here — use the{' '}
        <Link href='/origin/collections/'>collections page</Link> for that.
      </Alert>
      {ownedCollections && ownedCollections.length === 0 ? (
        <EmptyState />
      ) : (
        <Stack spacing={2}>
          {(ownedCollections ?? []).map((c) => (
            <CollectionCard
              key={c.id}
              collection={c}
              groups={allGroups ?? []}
            />
          ))}
        </Stack>
      )}
    </Box>
  );
};

const Header: React.FC = () => (
  <>
    <Breadcrumbs aria-label='breadcrumb' sx={{ mb: 2 }}>
      <Link href='/origin/'>Origin</Link>
      <Typography color='text.primary'>My collections</Typography>
    </Breadcrumbs>
    <Box
      display='flex'
      alignItems='center'
      justifyContent='space-between'
      mb={2}
      flexWrap='wrap'
      gap={1}
    >
      <Typography variant='h4'>My collections</Typography>
      <Link href='/origin/collections/onboard/'>
        <Button variant='contained'>Onboard new collection</Button>
      </Link>
    </Box>
  </>
);

const EmptyState: React.FC = () => (
  <Card variant='outlined'>
    <CardContent>
      <Typography variant='h6' gutterBottom>
        You don&apos;t own any collections yet
      </Typography>
      <Typography variant='body2' color='text.secondary' sx={{ mb: 2 }}>
        Onboard a new collection to set up its namespace, groups, and an invite
        link in one step. If you expected to own an existing collection, ask the
        current owner to transfer ownership to you (or ask the server
        administrator).
      </Typography>
    </CardContent>
    <CardActions>
      <Link href='/origin/collections/onboard/'>
        <Button variant='contained'>Onboard new collection</Button>
      </Link>
    </CardActions>
  </Card>
);

// CollectionCard composes a single owned-collection row: collection
// metadata across the top, ACL groups grouped by role below. We fetch
// the ACL on demand (per-card SWR) so the page renders a card list
// quickly and the ACL details fill in as they arrive — fewer waterfalls
// than fetching all ACLs up front in the parent.
const CollectionCard: React.FC<{
  collection: CollectionSummary;
  groups: Group[];
}> = ({ collection, groups }) => {
  const dispatch = useContext(AlertDispatchContext);
  const { data: acls, isLoading } = useSWR<CollectionAcl[] | undefined>(
    `collection-acl:${collection.id}`,
    () =>
      alertOnError(
        () => CollectionService.listAcls(collection.id),
        'Failed to load collection ACLs',
        dispatch
      )
  );

  return (
    <Card variant='outlined'>
      <CardContent>
        <Box
          display='flex'
          justifyContent='space-between'
          alignItems='flex-start'
          gap={2}
          mb={1}
        >
          <Box flexGrow={1} minWidth={0}>
            <Typography variant='h6' sx={{ wordBreak: 'break-word' }}>
              {collection.name}
            </Typography>
            <Typography
              variant='body2'
              color='text.secondary'
              sx={{ wordBreak: 'break-all' }}
            >
              {collection.namespace}
            </Typography>
          </Box>
          <Chip
            label={collection.visibility}
            size='small'
            color={collection.visibility === 'public' ? 'success' : 'default'}
            sx={{ textTransform: 'capitalize' }}
          />
        </Box>
        {collection.description && (
          <Typography variant='body2' color='text.secondary' sx={{ mb: 2 }}>
            {collection.description}
          </Typography>
        )}

        <Divider sx={{ my: 2 }} />

        <Typography variant='subtitle2' gutterBottom>
          Wired groups
        </Typography>
        {isLoading ? (
          <Skeleton variant='rounded' height={48} />
        ) : (
          <AclList acls={acls ?? []} groups={groups} />
        )}
      </CardContent>
      <CardActions>
        <Link
          href={`/origin/collections/edit/?id=${encodeURIComponent(collection.id)}`}
        >
          <Button size='small'>Manage collection</Button>
        </Link>
      </CardActions>
    </Card>
  );
};

// Render ACLs grouped by role. Each row resolves the ACL's groupId
// (which is a group *name*) against the visible groups list; when the
// group is in scope we link to its management page, otherwise we fall
// back to the bare name so the row still has a label.
const AclList: React.FC<{ acls: CollectionAcl[]; groups: Group[] }> = ({
  acls,
  groups,
}) => {
  if (acls.length === 0) {
    return (
      <Typography variant='body2' color='text.secondary'>
        No groups attached. Use the collection page to grant access.
      </Typography>
    );
  }
  // Group ACL rows by role for a one-glance summary; within each role
  // sort alphabetically by group identifier so the order is stable
  // across renders.
  const roles: CollectionAclRole[] = ['owner', 'write', 'read'];
  const byRole = new Map<CollectionAclRole, CollectionAcl[]>();
  for (const r of roles) byRole.set(r, []);
  for (const acl of acls) {
    if (!byRole.has(acl.role)) byRole.set(acl.role, []);
    byRole.get(acl.role)!.push(acl);
  }
  for (const r of byRole.values())
    r.sort((a, b) => a.groupId.localeCompare(b.groupId));

  // Index groups by name for the slug lookup. Group.name is what
  // ACLs reference (per GrantCollectionAcl in database/collection.go).
  const byName = new Map<string, Group>();
  for (const g of groups) byName.set(g.name, g);

  return (
    <Stack spacing={1.5}>
      {roles.map((role) => {
        const rows = byRole.get(role) ?? [];
        if (rows.length === 0) return null;
        return (
          <Box key={role}>
            <Box display='flex' alignItems='center' gap={1} mb={0.5}>
              <Chip
                label={role}
                size='small'
                color={
                  role === 'owner'
                    ? 'primary'
                    : role === 'write'
                      ? 'secondary'
                      : 'default'
                }
                sx={{ textTransform: 'capitalize' }}
              />
              <Typography variant='caption' color='text.secondary'>
                {rows.length} group{rows.length === 1 ? '' : 's'}
              </Typography>
            </Box>
            <Stack spacing={0.5} sx={{ pl: 1 }}>
              {rows.map((acl) => {
                const grp = byName.get(acl.groupId);
                const memberCount = grp?.members?.length;
                return (
                  <Box
                    key={`${acl.role}:${acl.groupId}`}
                    display='flex'
                    alignItems='center'
                    gap={1}
                  >
                    <Typography
                      variant='body2'
                      fontFamily='monospace'
                      sx={{ wordBreak: 'break-all' }}
                    >
                      {acl.groupId}
                    </Typography>
                    {typeof memberCount === 'number' && (
                      <Chip
                        label={`${memberCount} member${memberCount === 1 ? '' : 's'}`}
                        size='small'
                        variant='outlined'
                      />
                    )}
                    <Box ml='auto'>
                      {grp ? (
                        <Link
                          href={`/groups/view/?id=${encodeURIComponent(grp.id)}`}
                        >
                          <Button size='small'>Manage</Button>
                        </Link>
                      ) : (
                        <Typography variant='caption' color='text.disabled'>
                          (group not visible)
                        </Typography>
                      )}
                    </Box>
                  </Box>
                );
              })}
            </Stack>
          </Box>
        );
      })}
    </Stack>
  );
};

export default Page;
