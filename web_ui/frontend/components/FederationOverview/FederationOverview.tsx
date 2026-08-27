'use client';

import { Typography } from '@mui/material';
import useSWR from 'swr';

import getFederationUrls from '@/helpers/get/getFederationUrls';

import LinkBox from './LinkBox';

const FederationOverview = () => {
  const { data: federationUrls } = useSWR(
    'getFederationUrls',
    getFederationUrls,
    { fallbackData: {} }
  );

  const entries = Object.entries(federationUrls).filter(([, url]) => !!url);

  return (
    <>
      {entries.length > 0 ? (
        <Typography variant={'h4'} component={'h2'} mb={2}>
          Federation Overview
        </Typography>
      ) : null}
      {entries.map(([text, url]) => (
        <LinkBox key={text} href={url} text={text}></LinkBox>
      ))}
    </>
  );
};

export default FederationOverview;
