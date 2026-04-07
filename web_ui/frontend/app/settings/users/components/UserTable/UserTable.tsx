import {
  ClientTable,
  stringSort,
  dateSort,
  ClientTableImplementationProps,
} from '@/components/Table';
import { ClientTableProps } from '@/components/Table/ClientTable';
import { UserService, User } from '@/helpers/api';
import makeDeleteCell from '@/components/Table/DeleteCell/makeDeleteCell';
import makeEditCell from '@/components/Table/EditCell/makeEditCell';

const tableConfigGenerator = (mutate: () => void) => {
  return {
    username: { id: 'username', name: 'Username', sort: stringSort },
    sub: { id: 'sub', name: 'Sub', sort: stringSort },
    issuer: { id: 'issuer', name: 'Issuer', sort: stringSort },
    createdAt: { id: 'createdAt', name: 'Created At', sort: dateSort },
    delete: {
      id: 'delete',
      name: 'Delete',
      CellComponent: makeDeleteCell<User>({
        mutate,
        handleDelete: (user: User) => UserService.delete(user.id),
      }),
    },
    edit: {
      id: 'edit',
      name: 'Edit',
      CellComponent: makeEditCell<User>({
        href: (row) => `./edit?id=${row.id}`,
      }),
    },
  } as ClientTableProps<User>['columns'];
};

const UserTable = ({
  data,
  mutate,
}: Required<Pick<ClientTableImplementationProps<User>, 'data' | 'mutate'>>) => {
  return (
    <ClientTable
      data={data}
      columns={tableConfigGenerator(mutate)}
      defaultSort={{ columnId: 'createdAt', direction: 'desc' }}
    />
  );
};

export default UserTable;
