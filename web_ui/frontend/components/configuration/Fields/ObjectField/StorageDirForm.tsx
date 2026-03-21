import {
  FormProps,
  IntegerField,
  StorageDir,
  StringField,
} from '@/components/configuration';
import React, { useCallback } from 'react';
import { Box, Button } from '@mui/material';

const verifyForm = (x: StorageDir) => {
  return x.path != '';
};

const createDefaultStorageDir = (): StorageDir => {
  return {
    path: '',
    maxsize: '',
    highwatermarkpercentage: 0,
    lowwatermarkpercentage: 0,
  };
};

const StorageDirForm = ({ onSubmit, value }: FormProps<StorageDir>) => {
  const [storageDir, setStorageDir] = React.useState<StorageDir>(
    value || createDefaultStorageDir()
  );

  const submitHandler = useCallback(() => {
    if (!verifyForm(storageDir)) {
      return;
    }
    onSubmit(storageDir);
  }, [storageDir, onSubmit]);

  return (
    <>
      <Box my={2}>
        <StringField
          name={'Path'}
          onChange={(e) => setStorageDir({ ...storageDir, path: e })}
          value={storageDir.path}
        />
      </Box>
      <Box mb={2}>
        <StringField
          name={'MaxSize'}
          onChange={(e) => setStorageDir({ ...storageDir, maxsize: e })}
          value={storageDir.maxsize}
        />
      </Box>
      <Box mb={2}>
        <IntegerField
          name={'HighWaterMarkPercentage'}
          onChange={(e) =>
            setStorageDir({ ...storageDir, highwatermarkpercentage: e })
          }
          value={storageDir.highwatermarkpercentage}
        />
      </Box>
      <Box mb={2}>
        <IntegerField
          name={'LowWaterMarkPercentage'}
          onChange={(e) =>
            setStorageDir({ ...storageDir, lowwatermarkpercentage: e })
          }
          value={storageDir.lowwatermarkpercentage}
        />
      </Box>
      <Button type={'submit'} onClick={submitHandler}>
        Submit
      </Button>
    </>
  );
};

export default StorageDirForm;
