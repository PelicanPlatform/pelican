'use client';

import React, { useContext, useState } from 'react';

import { alertOnError } from '@/helpers/util';
import GroupForm from '../components/GroupAddForm';
import { AlertDispatchContext } from '@/components/AlertProvider';
import { GroupPost } from '@/helpers/api';
import SettingHeader from '@/app/settings/components/SettingHeader';
import { Breadcrumbs, Typography } from '@mui/material';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { fetchApi, GroupService, ApiID } from '@/helpers/api';
import useServiceSWR from '@/hooks/useServiceSWR';

const Page = () => {
  const searchParams = useSearchParams();
  const groupId = searchParams.get('id');

  const dispatch = useContext(AlertDispatchContext);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const router = useRouter();

  const { data: group, isLoading } = useServiceSWR(
    'Could not fetch group.',
    GroupService,
    'getOne',
    [groupId ? groupId : ''],
    { suspense: true }
  );

  // Ensure groupId is present before rendering form
  if (!group && !isLoading)
    return <Typography>Form must be opened with a defined id.</Typography>;

  return (
    <>
      <Breadcrumbs aria-label={'breadcrumb'} sx={{ mb: 2 }}>
        <Link href={'../'}>Groups</Link>
        <Typography sx={{ color: 'text.primary' }}>Edit</Typography>
      </Breadcrumbs>
      <SettingHeader title={'Edit Group'} />
      {isLoading || !group ? (
        <Typography>Loading...</Typography>
      ) : (
        <GroupForm
          group={group}
          onSubmit={async (group: GroupPost) => {
            setIsSubmitting(true);
            try {
              await alertOnError(
                async () => GroupService.patch(group.id, group),
                'Error Updating Group',
                dispatch,
                true
              );
              router.push('../view/?id=' + (await group.id));
            } finally {
              setIsSubmitting(false);
            }
          }}
          isSubmitting={isSubmitting}
        />
      )}
    </>
  );
};

export default Page;
