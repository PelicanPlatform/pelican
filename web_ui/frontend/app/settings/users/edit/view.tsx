'use client';

import React, { useContext, useState } from 'react';

import { alertOnError } from '@/helpers/util';
import UserForm from '../components/UserForm';
import { AlertDispatchContext } from '@/components/AlertProvider';
import SettingHeader from '@/app/settings/components/SettingHeader';
import { Breadcrumbs, Typography } from '@mui/material';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { UserService } from '@/helpers/api';
import type { User, UserPost } from '@/helpers/api';
import useServiceSWR from "@/hooks/useServiceSWR";

const Page = () => {
  const dispatch = useContext(AlertDispatchContext);

  const [isSubmitting, setIsSubmitting] = useState(false);

  const searchParams = useSearchParams()
  const userId = searchParams.get('id')

  const {data: user} = useServiceSWR(
    'Could not fetch user.',
    UserService.getOne,
    userId
  )

  // Ensure userId is present before rendering form
  if (!userId) return <Typography>Form must be opened with a defined id.</Typography>

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
            async () => UserService.patch(userId, user),
            'Error Creating New User',
            dispatch
          );
          if (response) {
            dispatch({
              type: 'openAlert',
              payload: {
                onClose: () => dispatch({ type: 'closeAlert' }),
                message: `Updated User`,
                alertProps: {
                  severity: 'success',
                },
              },
            });
          }
          setIsSubmitting(false);
        }}
        isSubmitting={isSubmitting}
      />
    </>
  );
};

export default Page;
