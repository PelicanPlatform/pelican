import { CellComponentProps, TableData } from '@/components/Table';
import EditCell from '@/components/Table/EditCell/EditCell';

interface MakeEditCellProps<R> {
  href: string | ((row: R) => string);
}

/**
 * A factory function that generates an EditCell component with a customizable href.
 * The href can be a static string or a function that takes the row data and returns a string.
 * @param href
 */
function makeEditCell<R extends TableData>({ href }: MakeEditCellProps<R>) {
  const hrefGetter = typeof href === 'string' ? () => href : href;

  const DynamicEditCell = ({ row }: CellComponentProps<R, any>) => {
    const href = hrefGetter(row);
    return <EditCell href={href} />;
  };

  DynamicEditCell.displayName = 'EditCell';

  return DynamicEditCell;
}

export default makeEditCell;
