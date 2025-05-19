import {ReactElement} from "react";
import ConfigurationProvider from "@/components/ConfigurationProvider/ConfigurationProvider";

import IssuerFlowContainer from "@/app/origin/issuer/components/IssuerFlowContainer";

import _metadata from '@/public/data/parameters.json';
import { ParameterMetadataList } from '@/components/configuration';

const Layout = ({children}: {children: ReactElement}) => {
	return (
		<ConfigurationProvider>
			<IssuerFlowContainer>
				{children}
			</IssuerFlowContainer>
		</ConfigurationProvider>
	)
}

export default Layout;