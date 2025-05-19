'use client';

import { createContext, Dispatch, useReducer } from 'react';
import { AlertPortalProps } from './AlertPortal';
import {AlertReducerAction} from "@/components/AlertProvider/index";
import alertReducer from "@/components/AlertProvider/alertReducer";

const defaultInlineAlertContext: AlertPortalProps | undefined = undefined;

export const InlineAlertContext = createContext<AlertPortalProps | undefined>(
		defaultInlineAlertContext
);

export const InlineAlertDispatchContext = createContext<Dispatch<AlertReducerAction>>(
		() => {}
);

export const GlobalAlertProvider = ({ children }: { children: React.ReactNode }) => {
	const [state, dispatch] = useReducer(alertReducer, defaultInlineAlertContext);

	return (
			<InlineAlertContext.Provider value={state}>
				<InlineAlertDispatchContext.Provider value={dispatch}>
					{children}
				</InlineAlertDispatchContext.Provider>
			</InlineAlertContext.Provider>
	);
};

export default GlobalAlertProvider;
