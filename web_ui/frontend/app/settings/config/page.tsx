import { merge } from 'lodash';

import Config from './Config';
import _metadata from '@/public/data/parameters.json';
import { ParameterMetadataList } from '@/components/configuration';

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
  return <Config metadata={parameterMetadata} />;
};

export default Page;
