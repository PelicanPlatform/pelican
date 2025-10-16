'use client';

import React, { useContext, useState } from 'react';

import { alertOnError } from '@/helpers/util';
import GroupForm from '../components/GroupAddForm';
import { AlertDispatchContext } from '@/components/AlertProvider';
import { GroupPost } from '@/types';
import SettingHeader from '@/app/settings/components/SettingHeader';
import { Breadcrumbs, Typography } from '@mui/material';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { fetchApi } from '@/helpers/api';

const Page = () => {
  const dispatch = useContext(AlertDispatchContext);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const router = useRouter();

  return (
    <>
      <Breadcrumbs aria-label={'breadcrumb'} sx={{ mb: 2 }}>
        <Link href={'../'}>Groups</Link>
        <Typography sx={{ color: 'text.primary' }}>Add</Typography>
      </Breadcrumbs>
      <SettingHeader title={'Add Group'} />
      <GroupForm
        onSubmit={async (user: GroupPost) => {
          setIsSubmitting(true);
          const response = await alertOnError(
            async () => addGroup(user),
            'Error Creating New Group',
            dispatch
          );
          if (response?.ok) {
            router.push('../view/?id=' + (await response.json()).id);
          }
          setIsSubmitting(false);
        }}
        isSubmitting={isSubmitting}
      />
    </>
  );
};

const addGroup = (group: GroupPost) => {
  return fetchApi(async () =>
    fetch('/api/v1.0/groups', {
      method: 'POST',
      body: JSON.stringify(group),
    })
  );
};

export default Page;
