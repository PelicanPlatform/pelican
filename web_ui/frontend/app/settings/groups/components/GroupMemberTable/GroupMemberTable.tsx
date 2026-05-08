import {
  ClientTable,
  stringSort,
  dateSort,
  ClientTableImplementationProps,
  CellComponentProps,
} from '@/components/Table';
import { ClientTableProps } from '@/components/Table/ClientTable';
import { ApiID, GroupMember, makeGroupMemberService } from '@/helpers/api';
import makeDeleteCell from '@/components/Table/DeleteCell/makeDeleteCell';
import DefaultCell from '@/components/Table/DefaultCell';

const tableConfigGenerator = (mutate: () => void, groupId: ApiID) => {
  const groupMemberService = makeGroupMemberService(groupId);

  return {
    name: {
      id: 'name',
      name: 'Name',
      value: (gm) => gm.user.username,
      sort: stringSort,
    },
    createdAt: {
      id: 'createdAt',
      name: 'Created At',
      sort: dateSort,
      CellComponent: ({
        value,
        row,
      }: CellComponentProps<GroupMember, 'createdAt'>) => (
        <DefaultCell row={row} value={new Date(value).toLocaleString()} />
      ),
    },
    createdBy: { id: 'createdBy', name: 'Created By', sort: stringSort },
    delete: {
      id: 'delete',
      name: 'Delete',
      CellComponent: makeDeleteCell<GroupMember>({
        mutate,
        handleDelete: (gm) => groupMemberService.delete(gm.userId),
        confirmButtonProps: {
          growDirection: 'left',
        },
      }),
    },
  } as ClientTableProps<GroupMember>['columns'];
};

const GroupMemberTable = ({
  data,
  mutate,
  groupId,
}: Required<
  Pick<ClientTableImplementationProps<GroupMember>, 'data' | 'mutate'>
> & { groupId: string }) => {
  return (
    <ClientTable
      data={data}
      columns={tableConfigGenerator(mutate, groupId)}
      defaultSort={{ columnId: 'createdAt', direction: 'desc' }}
    />
  );
};

export default GroupMemberTable;
