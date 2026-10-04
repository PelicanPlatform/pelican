import {
  FormProps,
  IntegerField,
  TieringTarget,
  StringField,
} from '@/components/configuration';
import React, { useCallback } from 'react';
import { Box, Button } from '@mui/material';

// A target is named either by a provider URL or by an S3 endpoint plus a
// bucket, mirroring how the cache parses Cache.TieringTargets.  Keyfiles
// apply only to the S3 form -- the cache refuses them alongside a provider
// URL, which takes its credentials from the provider's ambient chain -- so
// the form refuses that combination too rather than save a config the cache
// would not start with.
const verifyForm = (x: TieringTarget) => {
  const named = x.providerurl != '' || (x.serviceurl != '' && x.bucket != '');
  const keyfilesWithURL =
    x.providerurl != '' && (x.accesskeyfile != '' || x.secretkeyfile != '');
  return named && !keyfilesWithURL && x.maxsize != '';
};

const createDefaultTieringTarget = (): TieringTarget => {
  return {
    providerurl: '',
    serviceurl: '',
    region: '',
    bucket: '',
    prefix: '',
    urlstyle: '',
    accesskeyfile: '',
    secretkeyfile: '',
    maxsize: '',
    highwatermarkpercentage: 0,
    lowwatermarkpercentage: 0,
  };
};

const TieringTargetForm = ({ onSubmit, value }: FormProps<TieringTarget>) => {
  const [target, setTarget] = React.useState<TieringTarget>(
    value || createDefaultTieringTarget()
  );

  const submitHandler = useCallback(() => {
    if (!verifyForm(target)) {
      return;
    }
    onSubmit(target);
  }, [target, onSubmit]);

  return (
    <>
      <Box my={2}>
        <StringField
          name={'ProviderURL'}
          onChange={(e) => setTarget({ ...target, providerurl: e })}
          value={target.providerurl}
        />
      </Box>
      <Box mb={2}>
        <StringField
          name={'ServiceUrl'}
          onChange={(e) => setTarget({ ...target, serviceurl: e })}
          value={target.serviceurl}
        />
      </Box>
      <Box mb={2}>
        <StringField
          name={'Region'}
          onChange={(e) => setTarget({ ...target, region: e })}
          value={target.region}
        />
      </Box>
      <Box mb={2}>
        <StringField
          name={'Bucket'}
          onChange={(e) => setTarget({ ...target, bucket: e })}
          value={target.bucket}
        />
      </Box>
      <Box mb={2}>
        <StringField
          name={'Prefix'}
          onChange={(e) => setTarget({ ...target, prefix: e })}
          value={target.prefix}
        />
      </Box>
      <Box mb={2}>
        <StringField
          name={'UrlStyle'}
          onChange={(e) => setTarget({ ...target, urlstyle: e })}
          value={target.urlstyle}
        />
      </Box>
      <Box mb={2}>
        <StringField
          name={'AccessKeyfile'}
          onChange={(e) => setTarget({ ...target, accesskeyfile: e })}
          value={target.accesskeyfile}
        />
      </Box>
      <Box mb={2}>
        <StringField
          name={'SecretKeyfile'}
          onChange={(e) => setTarget({ ...target, secretkeyfile: e })}
          value={target.secretkeyfile}
        />
      </Box>
      <Box mb={2}>
        <StringField
          name={'MaxSize'}
          onChange={(e) => setTarget({ ...target, maxsize: e })}
          value={target.maxsize}
        />
      </Box>
      <Box mb={2}>
        <IntegerField
          name={'HighWaterMarkPercentage'}
          onChange={(e) => setTarget({ ...target, highwatermarkpercentage: e })}
          value={target.highwatermarkpercentage}
        />
      </Box>
      <Box mb={2}>
        <IntegerField
          name={'LowWaterMarkPercentage'}
          onChange={(e) => setTarget({ ...target, lowwatermarkpercentage: e })}
          value={target.lowwatermarkpercentage}
        />
      </Box>
      <Button type={'submit'} onClick={submitHandler}>
        Submit
      </Button>
    </>
  );
};

export default TieringTargetForm;
