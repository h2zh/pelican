import DowntimeCardList from '@/components/Downtime/DowntimeCardList';
import ServerDowntimeCard from '@/components/Downtime/Server/ServerDowntimeCard';
import useApiSWR from '@/hooks/useApiSWR';
import { DowntimeGet } from '@/types';
import { ServerDowntimeKey } from '@/components/Downtime';
import { getDowntime } from '@/helpers/api';

const RegistryDowntimeList = ({ data }: { data?: DowntimeGet[] }) => {
  return <DowntimeCardList Card={ServerDowntimeCard} data={data} />;
};

export default RegistryDowntimeList;
