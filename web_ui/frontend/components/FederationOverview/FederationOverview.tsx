'use client';

import { Typography } from '@mui/material';
import useSWR from 'swr';

import getFederationUrls from '@/helpers/get/getFederationUrls';

import LinkBox from './LinkBox';

const FederationOverview = () => {
  const { data: federationUrls, error } = useSWR(
    'getFederationUrls',
    getFederationUrls,
    { fallbackData: [] }
  );

  return (
    <>
      {!Object.values(federationUrls).every((x) => x == undefined) ? (
        <Typography variant={'h4'} component={'h2'} mb={2}>
          Federation Overview
        </Typography>
      ) : null}
      {Object.entries(federationUrls).map(([text, url]) => {
        if (url) {
          return <LinkBox key={text} href={url} text={text}></LinkBox>;
        }
      })}
    </>
  );
};

export default FederationOverview;
