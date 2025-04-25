import DirectorDowntimeCard from '@/components/Downtime/Director/DirectorDowntimeCard';
import DowntimeCardList from '@/components/Downtime/DowntimeCardList';
import { DowntimeGet } from '@/types';

const DirectorDowntimeList = ({data}: {data?: DowntimeGet[]}) => {

  return <DowntimeCardList Card={DirectorDowntimeCard} data={data} />;
};

export default DirectorDowntimeList;
