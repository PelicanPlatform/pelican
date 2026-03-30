import { ClientTable, ColumnConfig, stringSort, dateSort } from '@/components/Table';
import {ClientTableProps} from "@/components/Table/ClientTable";
import { UserService, User, fetchApi } from '@/helpers/api';
import makeDeleteUserCell from './makeDeleteUserCell';
import EditUserCell from './EditUserCell';

interface UserTableProps {
  users: User[],
  mutate: () => void
}

const userTableConfigGenerator = (mutate: () => void) => {
  return {
    username: { id: 'username', name: 'Username', sort: stringSort },
    sub: { id: 'sub', name: 'Sub', sort: stringSort },
    issuer: { id: 'issuer', name: 'Issuer', sort: stringSort },
    createdAt: { id: 'createdAt', name: 'Created At', sort: dateSort },
    delete: { id: 'delete', name: 'Delete', CellComponent: makeDeleteUserCell(mutate) },
    edit: { id: 'edit', name: 'Edit', CellComponent: EditUserCell }
  } as ClientTableProps<User>['columns'];
};

const UserTable = ({users, mutate}: UserTableProps) => {
  return <ClientTable data={users} columns={userTableConfigGenerator(mutate)} defaultSort={{columnId: "createdAt", direction: "desc"}} />;
}

export default UserTable;
