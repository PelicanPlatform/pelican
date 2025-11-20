'use client';

import React, { useContext, useState } from 'react';

import { alertOnError } from '@/helpers/util';
import UserForm from '../components/UserForm';
import { AlertDispatchContext } from '@/components/AlertProvider';
import { UserPost } from '@/types';
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
        <Link href={'../'}>Users</Link>
        <Typography sx={{ color: 'text.primary' }}>Add</Typography>
      </Breadcrumbs>
      <SettingHeader title={'Add User'} />
      <UserForm
        onSubmit={async (user: UserPost) => {
          setIsSubmitting(true);
          const response = await alertOnError(
            async () => addUser(user),
            'Error Creating New User',
            dispatch
          );
          if (response?.ok) {
            dispatch({
              type: 'openAlert',
              payload: {
                onClose: () => dispatch({ type: 'closeAlert' }),
                message: `Created User`,
                alertProps: {
                  severity: 'success',
                },
              },
            });
            router.push('../');
          }
          setIsSubmitting(false);
        }}
        isSubmitting={isSubmitting}
      />
    </>
  );
};

const addUser = (user: UserPost) => {
  return fetchApi(async () =>
    fetch('/api/v1.0/users', { method: 'POST', body: JSON.stringify(user) })
  );
};

export default Page;
