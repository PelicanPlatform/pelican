import { merge } from 'lodash';

import Config from './Config';
import _metadata from '@/public/data/parameters.json';
import { ParameterMetadataList } from '@/components/configuration';
import AuthenticatedContent from '@/components/layout/AuthenticatedContent';

const getMetadata = async () => {
  const metadataList = _metadata as unknown as ParameterMetadataList;
  const visibleMetadataList = metadataList.filter(
    (metadata) => !Object.values(metadata)[0].hidden
  );
  // @ts-ignore
  return merge(...visibleMetadataList);
};

// Config is an administration page, so it lives under /settings/ and inherits
// that shell (gate, sub-navigation, rail behaviour) from app/settings/layout.tsx
// rather than carrying a layout of its own. The title is declared here because
// there is no layout left to declare it.
export const metadata = {
  title: 'Configuration',
};

const Page = async () => {
  // Named distinctly from the exported `metadata` above, which is Next's
  // page metadata and a different thing entirely.
  const parameterMetadata = await getMetadata();
  // Admin-only, tightening the Settings shell's gate, which also admits
  // pelican.log_read holders for the Logs page. GET /api/v1.0/config is
  // admin-only, so anyone else got an empty form, a Restart Server button
  // and a 403 toast. The gate wraps <Config> rather than sitting inside it
  // because Config fetches the config as it mounts: a gate inside it would
  // hide the form but still send the request.
  return (
    <AuthenticatedContent redirect allowedRoles={['admin']}>
      <Config metadata={parameterMetadata} />
    </AuthenticatedContent>
  );
};

export default Page;
