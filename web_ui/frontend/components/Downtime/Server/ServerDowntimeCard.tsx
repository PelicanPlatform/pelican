import DowntimeCard from '../Card';
import { DowntimeCardProps } from '@/components/Downtime/type';

const ServerDowntimeCard = ({ downtime }: DowntimeCardProps) => {
  return <DowntimeCard editable downtime={downtime} />;
};

export default ServerDowntimeCard;
