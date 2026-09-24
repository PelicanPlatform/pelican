import {
  FormProps,
  IntegerField,
  S3StorageTarget,
  StringField,
} from '@/components/configuration';
import React, { useCallback } from 'react';
import { Box, Button } from '@mui/material';

const verifyForm = (x: S3StorageTarget) => {
  return x.serviceurl != '' && x.bucket != '' && x.maxsize != '';
};

const createDefaultS3StorageTarget = (): S3StorageTarget => {
  return {
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

const S3StorageTargetForm = ({
  onSubmit,
  value,
}: FormProps<S3StorageTarget>) => {
  const [target, setTarget] = React.useState<S3StorageTarget>(
    value || createDefaultS3StorageTarget()
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

export default S3StorageTargetForm;
