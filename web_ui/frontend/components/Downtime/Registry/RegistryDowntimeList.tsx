import RegistryDowntimeCard from '@/components/Downtime/Registry/RegistryDowntimeCard';
import DowntimeCardList from '@/components/Downtime/DowntimeCardList';
import useApiSWR from '@/hooks/useApiSWR';
import { DowntimeGet } from '@/types';
import { ServerDowntimeKey } from '@/components/Downtime';
import { getDowntime } from '@/helpers/api';

const RegistryDowntimeList = () => {
  const { data } = useApiSWR<DowntimeGet[]>(
    'Failed to fetch downtimes',
    ServerDowntimeKey,
    getDowntime
  );

  return <DowntimeCardList Card={RegistryDowntimeCard} data={data} />;
};

export default RegistryDowntimeList;
