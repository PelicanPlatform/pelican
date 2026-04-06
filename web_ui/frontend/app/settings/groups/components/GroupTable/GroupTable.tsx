import {
  ClientTable,
  stringSort,
  dateSort,
  ClientTableImplementationProps,
} from '@/components/Table';
import { ClientTableProps } from '@/components/Table/ClientTable';
import { Group } from '@/helpers/api';
import { makeViewCell } from '@/components/Table/ViewCell';

const tableConfigGenerator = (mutate: () => void) => {
  return {
    view: {
      id: 'view',
      name: 'View',
      CellComponent: makeViewCell({ href: (g: Group) => `./view?id=${g.id}` }),
    },
    name: { id: 'name', name: 'Name', sort: stringSort },
    createdAt: {
      id: 'createdAt',
      name: 'Created At',
      sort: dateSort,
      value: (r) => new Date(r.createdAt).toLocaleString(),
    },
    createdBy: {
      id: 'createdBy',
      name: 'Created By',
      sort: dateSort,
      value: (r) => new Date(r.createdAt).toLocaleString(),
    },
    members: {
      id: 'members',
      name: 'Members',
      value: (r: Group) => r?.members?.length,
    },
  } as ClientTableProps<Group>['columns'];
};

const GroupTable = ({
  data,
  mutate,
}: ClientTableImplementationProps<Group>) => {
  return (
    <ClientTable
      data={data}
      columns={tableConfigGenerator(mutate)}
      defaultSort={{ columnId: 'createdAt', direction: 'desc' }}
    />
  );
};

export default GroupTable;
