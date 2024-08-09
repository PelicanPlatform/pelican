import { merge } from 'lodash';

import Config from './Config';
import _metadata from '@/public/data/parameters.json';
import { ParameterMetadataList } from '@/components/configuration';

const getMetadata = async () => {
  const metadataList = _metadata as unknown as ParameterMetadataList;
  // @ts-ignore
  return merge(...metadataList);
};

const Page = async () => {
  const metadata = await getMetadata();
  return <Config metadata={metadata} />;
};

export default Page;
