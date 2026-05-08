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

const Page = async () => {
  const metadata = await getMetadata();
  return <Config metadata={metadata} />;
};

export default Page;
