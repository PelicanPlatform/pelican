import { AlertPortalProps } from './AlertPortal';
export {default as Global} from "./AlertProvider"

export type AlertReducerAction =
		| closeAlertAction
		| openErrorAlertAction
		| openAlertAction;

type closeAlertAction = {
	type: 'closeAlert';
};

type openErrorAlertAction = {
	type: 'openErrorAlert';
	payload: {
		title: string;
		error: string;
		onClose: () => void;
	};
};

type openAlertAction = {
	type: 'openAlert';
	payload: AlertPortalProps;
};