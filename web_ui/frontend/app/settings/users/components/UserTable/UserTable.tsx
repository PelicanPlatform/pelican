import { TableCell, Typography } from '@mui/material';
import {
  ClientTable,
  stringSort,
  dateSort,
  ClientTableImplementationProps,
  CellComponentProps,
} from '@/components/Table';
import { ClientTableProps } from '@/components/Table/ClientTable';
import { UserService, User, GroupMember } from '@/helpers/api';
import makeDeleteCell from '@/components/Table/DeleteCell/makeDeleteCell';
import makeEditCell from '@/components/Table/EditCell/makeEditCell';
import DefaultCell from '@/components/Table/DefaultCell';

// UserCell renders "Display Name" on the first line and "username"
// on a second line in monospace below it. Per the user/group design
// contract, every authz-affecting control should show both labels
// together so admins can disambiguate two users with similar display
// names ("Brian B."). This preserves the existing username-sort
// (column id is still "username") while making the visual unit a
// single cell rather than two columns the eye has to correlate.
const UserCell = ({ row }: CellComponentProps<User, 'username'>) => (
  <TableCell>
    {row.displayName ? (
      <>
        <Typography variant='body2'>{row.displayName}</Typography>
        <Typography
          variant='caption'
          color='text.secondary'
          sx={{ fontFamily: 'monospace' }}
        >
          {row.username}
        </Typography>
      </>
    ) : (
      <Typography variant='body2' sx={{ fontFamily: 'monospace' }}>
        {row.username}
      </Typography>
    )}
  </TableCell>
);

const tableConfigGenerator = (mutate: () => void) => {
  return {
    // Single combined column. The cell renders "Display Name" + "username"
    // stacked; the sort still keys off the username string so admins
    // looking for a specific machine-name can find it.
    username: {
      id: 'username',
      name: 'User',
      sort: stringSort,
      CellComponent: UserCell,
    },
    sub: { id: 'sub', name: 'Sub', sort: stringSort },
    issuer: { id: 'issuer', name: 'Issuer', sort: stringSort },
    createdAt: {
      id: 'createdAt',
      name: 'Created At',
      sort: dateSort,
      CellComponent: ({
        value,
        row,
      }: CellComponentProps<User, 'createdAt'>) => (
        <DefaultCell row={row} value={new Date(value).toLocaleString()} />
      ),
    },
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
