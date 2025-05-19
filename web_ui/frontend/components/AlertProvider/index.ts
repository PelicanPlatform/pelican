import { AlertPortalProps } from './AlertPortal';
export {default as GlobalAlertProvider, GlobalAlertDispatchContext, GlobalAlertContext} from "./GlobalAlertProvider"
export {default as InlineAlertProvider, InlineAlertDispatchContext, InlineAlertContext} from "./InlineAlertProvider"

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
