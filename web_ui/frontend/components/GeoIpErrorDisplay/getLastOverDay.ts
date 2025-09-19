import { query_raw, VectorResponseData } from '@/components';

const getLastOverDay = async (metric: string) => {
  return (await query_raw<VectorResponseData>(`last_over_time(${metric}}[1d])`)).data.result;
}

export default getLastOverDay;
