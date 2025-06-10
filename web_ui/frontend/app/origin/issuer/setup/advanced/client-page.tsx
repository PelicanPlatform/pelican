'use client';

import { Typography } from '@mui/material';
import React, {use, useContext} from 'react';
import { ParameterMetadataRecord } from '@/components/configuration';
import {ConfigDisplay} from "@/app/config/components";
import {ConfigurationContext} from "@/components/ConfigurationProvider/ConfigurationProvider";

const fields = [
  'Issuer.TomcatLocation',
  'Issuer.ScitokensServerLocation',
  'Issuer.QDLLocation',
  'Issuer.IssuerClaimValue',
];


const ClientPage = ({ metadata }: { metadata: ParameterMetadataRecord }) => {

  const { configuration, patch, setPatch } = useContext(ConfigurationContext);

  console.log(configuration, patch)

  return (
    <>
      <Typography variant={'subtitle1'} component={'h2'} gutterBottom>
        Advanced Issuer Configuration
      </Typography>
      <Typography variant={'body1'} gutterBottom>
        This set of configuration is not required for the basic setup of the
        Origin Issuer. It is provided for advanced users that wish to further
        customize the behavior of the Origin Issuer.
      </Typography>
      {fields.map((field) => {
        return <ConfigDisplay
            key={field}
            config={configuration}
            patch={patch}
            metadata={{
              [field]:
                  metadata[field],
            }}
            onChange={setPatch}
            omitLabels={true}
            showDescription={false}
        />
      })}
    </>
  );
};

export default ClientPage;
