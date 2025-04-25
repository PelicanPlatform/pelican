import DirectorDowntimeCard from '@/components/Downtime/Director/DirectorDowntimeCard';
import DowntimeCardList from '@/components/Downtime/DowntimeCardList';
import useApiSWR from '@/hooks/useApiSWR';
import { DowntimeGet } from '@/types';
import { ServerDowntimeKey } from '@/components/Downtime';
import { getDowntime } from '@/helpers/api';

const DirectorDowntimeList = () => {
  const { data } = useApiSWR<DowntimeGet[]>(
    'Failed to fetch downtimes',
    ServerDowntimeKey,
    getDowntime
  );

  return <DowntimeCardList Card={DirectorDowntimeCard} data={data} />;
};

export default DirectorDowntimeList;
