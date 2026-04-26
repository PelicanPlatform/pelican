import useSWR from 'swr';
import DowntimeCard from '../Card';
import { DowntimeCardProps } from '@/components/Downtime/type';
import { getUser } from '@/helpers/login';

const ServerDowntimeCard = ({ downtime }: DowntimeCardProps) => {
  const { data: user } = useSWR('getUser', getUser);
  return <DowntimeCard editable={user?.role === 'admin'} downtime={downtime} />;
};

export default ServerDowntimeCard;
