import RegistryDowntimeCard from '@/components/Downtime/Registry/RegistryDowntimeCard';
import DowntimeCardList from '@/components/Downtime/DowntimeCardList';
import { DowntimeGet } from '@/types';

const RegistryDowntimeList = ({ data }: { data?: DowntimeGet[] }) => {
  return <DowntimeCardList Card={RegistryDowntimeCard} data={data} />;
};

export default RegistryDowntimeList;
