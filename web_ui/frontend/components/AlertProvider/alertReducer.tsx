import { AlertPortalProps } from '@/components/AlertProvider/AlertPortal';
import { AlertReducerAction } from '@/components/AlertProvider/index';
import CodeBlock from '@/components/CodeBlock';

const alertReducer = (
  state: AlertPortalProps | undefined,
  action: AlertReducerAction
): AlertPortalProps | undefined => {
  switch (action.type) {
    case 'closeAlert':
      return undefined;
    case 'openErrorAlert':
      const { title, error, onClose } = action.payload;

      return {
        title,
        onClose,
        message: <CodeBlock>{error}</CodeBlock>,
        alertProps: {
          severity: 'error',
        },
      };
    case 'openAlert':
      return action.payload;
    default:
      return state;
  }
};

export default alertReducer;
