import DowntimeCard from '../Card';
import { DowntimeCardProps } from '@/components/Downtime/type';

const RegistryDowntimeCard = ({ downtime }: DowntimeCardProps) => {
  return <DowntimeCard editable federationLevel downtime={downtime} />;
};

export default RegistryDowntimeCard;
