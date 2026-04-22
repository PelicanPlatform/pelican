import { CellComponentProps, TableData } from '@/components/Table';
import ViewCell from '@/components/Table/ViewCell/ViewCell';

interface MakeViewCellProps<R> {
  href: string | ((row: R) => string);
}

/**
 * A factory function that generates an ViewCell component with a customizable href.
 * The href can be a static string or a function that takes the row data and returns a string.
 * @param href
 */
function makeViewCell<R extends TableData>({ href }: MakeViewCellProps<R>) {
  const hrefGetter = typeof href === 'string' ? () => href : href;

  const DynamicViewCell = ({ row }: CellComponentProps<R, any>) => {
    const href = hrefGetter(row);
    return <ViewCell href={href} />;
  };

  DynamicViewCell.displayName = 'ViewCell';

  return DynamicViewCell;
}

export default makeViewCell;
