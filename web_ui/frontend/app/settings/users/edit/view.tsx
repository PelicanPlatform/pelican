'use client';

import React, { useContext, useState } from 'react';

import { alertOnError } from '@/helpers/util';
import UserForm from '../components/UserForm';
import { AlertDispatchContext } from '@/components/AlertProvider';
import SettingHeader from '@/app/settings/components/SettingHeader';
import { Breadcrumbs, Typography } from '@mui/material';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { UserPatch, UserService } from '@/helpers/api';
import useServiceSWR from '@/hooks/useServiceSWR';

const Page = () => {
  const router = useRouter();
  const dispatch = useContext(AlertDispatchContext);

  const searchParams = useSearchParams();
  const userId = searchParams.get('id');

  const { data: user } = useServiceSWR(
    'Could not fetch user.',
    UserService,
    'getOne',
    [userId ?? undefined],
    { suspense: true }
  );

  const [isSubmitting, setIsSubmitting] = useState(false);

  // Ensure userId is present before rendering form
  if (!userId)
    return <Typography>Form must be opened with a defined id.</Typography>;

  return (
    <>
      <Breadcrumbs aria-label={'breadcrumb'} sx={{ mb: 2 }}>
        <Link href={'../'}>Users</Link>
        <Typography sx={{ color: 'text.primary' }}>Edit</Typography>
      </Breadcrumbs>
      <SettingHeader title={'Edit User'} />
      <UserForm
        user={user}
        onSubmit={async (user: UserPatch) => {
          setIsSubmitting(true);
          try {
            await alertOnError(
              async () => UserService.patch(userId, user),
              'Error Editing User',
              dispatch,
              true
            );
            dispatch({
              type: 'openAlert',
              payload: {
                onClose: () => dispatch({ type: 'closeAlert' }),
                message: `Updated User`,
                autoHideDuration: 3000,
                alertProps: {
                  severity: 'success',
                },
              },
            });
            router.push('../');
          } catch (error) {
            setIsSubmitting(false);
          }
        }}
        isSubmitting={isSubmitting}
      />
    </>
  );
};

export default Page;
