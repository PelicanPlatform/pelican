import { getConfig } from '@/helpers/api';

const getOverriddenGeoIps = async () => {
  let tries = 0;
  while (tries < 2) {
    try {
      const response = await getConfig();
      const config = await response.json();
      return { GeoIPOverrides: config.GeoIPOverrides };
    } catch (e) {
      tries++;
      await new Promise((r) => setTimeout(r, 10 ** tries * 500));
    }
  }
};

export default getOverriddenGeoIps;
