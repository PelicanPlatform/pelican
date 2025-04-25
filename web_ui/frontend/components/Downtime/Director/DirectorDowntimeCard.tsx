import DowntimeCard from '../Card';
import { DowntimeCardProps } from '@/components/Downtime/type';

const DirectorDowntimeCard = ({ downtime }: DowntimeCardProps) => {
  return <DowntimeCard downtime={downtime} federationLevel={true} />;
};

export default DirectorDowntimeCard;
