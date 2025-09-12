import { ServerGeneral } from '@/types';

const serverHasError = (server?: ServerGeneral) => {
  return (
    server?.healthStatus === 'Error' ||
    ['shutting down', 'critical', 'degraded', 'warning'].includes(
      server?.serverStatus || ''
    )
  );
};

export default serverHasError;
