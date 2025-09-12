import { getObjectValue } from '@/helpers/util';
import { getConfig } from '@/helpers/api';
import { WellKnownConfiguration } from '@/types';
import { Config } from '@/components/configuration';


/**
 * Get federation URLs
 */
export const getFederationUrls = async () => {
  try {
    // Get the configuration
    const response = await getConfig();
    const config = (await response.json()) as Config;

    // Map the configuration to federation URLs
    const federationUrls = configurationToFederationUrls(config);

    // If there is a discovery URL, attempt to get the well-known configuration
    const discoveryUrl = getObjectValue<string>(config, [
      'Federation',
      'DiscoveryUrl',
    ]);
    const discoveredUrls = discoveryUrl
      ? await discoverConfiguration(discoveryUrl)
      : {};

    console.log(discoveredUrls);

    // Merge the two sets of URLs, with discovered URLs taking precedence
    return {
      ...federationUrls,
      ...discoveredUrls,
    };
  } catch (e) {
    console.error(e);
    return [];
  }
};

const configurationToFederationUrls = (config: Config) => {
  return UrlData.reduce(
    (acc, { key, text }) => {
      const url = getObjectValue<string>(config, key);
      if (url) {
        acc[text] = url;
      }
      return acc;
    },
    {} as { [key: string]: string }
  );
};

const UrlData = [
  { key: ['Federation', 'NamespaceUrl'], text: 'Namespace Registry' },
  { key: ['Federation', 'DirectorUrl'], text: 'Director' },
  { key: ['Federation', 'RegistryUrl'], text: 'Registry' },
  { key: ['Federation', 'JwkUrl'], text: 'JWK' },
];

/**
 * Discovery URL handler
 *
 * Goes to the discovery URL and fetches the well-known pelican configuration
 * then maps the values to friendly names
 */
export const discoverConfiguration = async (discoveryUrl: string) => {
  try {
    // Go to the discovery endpoint and get the well-known configuration
    const url = new URL('/.well-known/pelican-configuration', discoveryUrl);
    const response = await fetch(url.toString());
    if (!response.ok) {
      throw new Error(`Error fetching discovery URL: ${response.statusText}`);
    }
    const wellKnownConfiguration =
      (await response.json()) as WellKnownConfiguration;

    // Consume the well-known configuration and map to friendly names
    return Object.keys(DISCOVERY_LABEL_MAP).reduce(
      (acc, key) => {
        const typedKey = key as keyof WellKnownConfiguration;
        if (wellKnownConfiguration[typedKey]) {
          acc[DISCOVERY_LABEL_MAP[typedKey]] = wellKnownConfiguration[
            typedKey
          ] as string;
        }
        return acc;
      },
      {} as { [key: string]: string }
    );
  } catch {
    return {};
  }
};

const DISCOVERY_LABEL_MAP: WellKnownConfiguration = {
  director_endpoint: 'Director',
  namespace_registration_endpoint: 'Registry',
  jwks_uri: 'JWK',
};

export default getFederationUrls;
