import { WellKnownConfiguration } from '@/types';

interface FederationInfo extends WellKnownConfiguration {
  discovery_endpoint?: string;
  broker_endpoint?: string;
}

const LABEL_MAP: { key: keyof FederationInfo; text: string }[] = [
  { key: 'director_endpoint', text: 'Director' },
  { key: 'namespace_registration_endpoint', text: 'Registry' },
  { key: 'jwks_uri', text: 'JWK' },
];

/**
 * Get federation URLs from the local server's /api/v1.0/federation endpoint.
 *
 * The endpoint returns the resolved federation discovery info and is
 * accessible to any authenticated user, so non-admin dashboards can render
 * director/registry links without needing access to the admin-only /config.
 */
export const getFederationUrls = async (): Promise<{
  [key: string]: string;
}> => {
  try {
    const response = await fetch('/api/v1.0/federation');
    if (!response.ok) {
      return {};
    }
    const info = (await response.json()) as FederationInfo;
    return LABEL_MAP.reduce(
      (acc, { key, text }) => {
        const url = info[key];
        if (url) {
          acc[text] = url;
        }
        return acc;
      },
      {} as { [key: string]: string }
    );
  } catch (e) {
    console.error(e);
    return {};
  }
};

export default getFederationUrls;
