import DowntimeCardList from '@/components/Downtime/DowntimeCardList';
import ServerDowntimeCard from '@/components/Downtime/Server/ServerDowntimeCard';
import { DowntimeGet } from '@/types';

const RegistryDowntimeList = ({ data }: { data?: DowntimeGet[] }) => {
  return <DowntimeCardList Card={ServerDowntimeCard} data={data} />;
};

export default RegistryDowntimeList;
