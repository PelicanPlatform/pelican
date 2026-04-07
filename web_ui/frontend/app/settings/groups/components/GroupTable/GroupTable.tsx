import {
  ClientTable,
  stringSort,
  dateSort,
  ClientTableImplementationProps,
  CellComponentProps,
  numberSort,
} from '@/components/Table';
import { ClientTableProps } from '@/components/Table/ClientTable';
import { Group } from '@/helpers/api';
import { makeViewCell } from '@/components/Table/ViewCell';
import DefaultCell from '@/components/Table/DefaultCell';

const tableConfig = {
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
    CellComponent: ({ value, row }: CellComponentProps<Group, 'createdBy'>) => (
      <DefaultCell row={row} value={new Date(value).toLocaleString()} />
    ),
  },
  createdBy: {
    id: 'createdBy',
    name: 'Created By',
    sort: stringSort,
  },
  members: {
    id: 'members',
    name: 'Members',
    value: (r: Group) => r?.members?.length,
    sort: numberSort,
  },
} as ClientTableProps<Group>['columns'];

const GroupTable = ({ data }: ClientTableImplementationProps<Group>) => {
  return (
    <ClientTable
      data={data}
      columns={tableConfig}
      defaultSort={{ columnId: 'createdAt', direction: 'desc' }}
    />
  );
};

export default GroupTable;
