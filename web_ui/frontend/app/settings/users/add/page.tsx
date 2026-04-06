'use client';

import React, { useContext, useState } from 'react';

import { alertOnError } from '@/helpers/util';
import UserForm from '../components/UserForm';
import { AlertDispatchContext } from '@/components/AlertProvider';
import SettingHeader from '@/app/settings/components/SettingHeader';
import { Breadcrumbs, Typography } from '@mui/material';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { UserService, UserPost } from '@/helpers/api';

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
            async () => UserService.post(user),
            'Error Creating New User',
            dispatch
          );
          if (response) {
            dispatch({
              type: 'openAlert',
              payload: {
                onClose: () => dispatch({ type: 'closeAlert' }),
                message: `Created User`,
                autoHideDuration: 3000,
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

export default Page;
