import { Config } from '@/components/configuration';

export const getConfig = async (): Promise<Config> => {
  let response = await fetch('/api/v1.0/config');
  return await response.json();
};

/**
 * Recurse into the config object
 */
