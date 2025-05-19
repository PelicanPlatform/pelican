"use client"

import {Autocomplete, Box, TextField, Typography} from "@mui/material";
import {use, useContext} from 'react'
import {ConfigurationContext} from "@/components/ConfigurationProvider/ConfigurationProvider";

const issuers = [
	{ issuer: "CILogon", label: "https://cilogon.org" },
	{ issuer: "Google", label: "https://accounts.google.com" },
	{ issuer: "Microsoft Azure AD", label: "https://login.windows.net/common" }
];

const providerConfiguration = {
	"OIDC.Issuer": "",
	"OIDC.DeviceAuthEndpoint": "",
	"OIDC.TokenEndpoint": "",
  "OIDC.AuthorizationEndpoint": "",
	"OIDC.UserInfoEndpoint": ""
}

const Page = () => {

	const {merged, patch, setPatch} = useContext(ConfigurationContext)

	const issuerIsSet = merged["OIDC.Issuer"] !== "" && merged["OIDC.Issuer"] !== undefined;

	return (<>
		<Typography variant={"subtitle1"} component={"h2"} gutterBottom>
			OpenID Connect Provider Configuration
		</Typography>
		<Typography variant={"body1"} gutterBottom>
			This set of configuration provides a framework for how we should communicate with the OpenID Provider you registered
			your client with. The endpoints we wish to communicate with are enumerated below.
		</Typography>
		<Typography variant={"body1"} gutterBottom>
			Pelican has two methods to provide this information.
		</Typography>
		<Typography variant={"h6"} gutterBottom>
			1. Issuer URL with Document Discovery
		</Typography>
		<Typography variant={"body2"} gutterBottom>
			OpenID Connect allows providers to provide a single JSON document which enumerates the necessary communication
			endpoints. This document is available at <b>Issuer</b>/.well-known/openid-configuration where <b>Issuer</b> is the URL
			of the provider service.
		</Typography>
		<Typography variant={"body2"} gutterBottom>
			For example, if your provider is CILogon, you would provide the issuer URL as <b>https://cilogon.org</b>. We can verify that
			they provide the discovery document by visiting <b>https://cilogon.org</b>/.well-known/openid-configuration.
		</Typography>
		<Typography variant={"h6"} gutterBottom>
			2. Manual Endpoint Entry
		</Typography>
		<Typography variant={"body2"} gutterBottom>
			If your provider does not support the discovery document, you can manually enter the endpoints that would have been
			found there.
		</Typography>
		<Box mt={3}>
			<Autocomplete
					id="issuer"
					disablePortal
					freeSolo
					options={issuers}
					onChange={(event, value) => {setPatch({"OIDC.Issuer": typeof value == "string" ? value : value?.label})}}
					renderInput={(params) => (
							<TextField
									{...params}
									label="Issuer"
									helperText={patch["OIDC.Issuer"] && <a href={patch["OIDC.Issuer"] + "/.well-known/openid-configuration"} target="_blank">{patch["OIDC.Issuer"] + "/.well-known/openid-configuration"}</a>}

							/>
					)}
					value={merged["OIDC.Issuer"] as string}
			/>
			<TextField
					id="deviceAuthEndpoint"
					label="Device Auth Endpoint"
					helperText={issuerIsSet && "Disabled when Issuer is set"}
					value={merged["OIDC.DeviceAuthEndpoint"] as string}
					onChange={(event) => {setPatch({"OIDC.DeviceAuthEndpoint": event.target.value})}}
					margin="normal"
					fullWidth
					variant="outlined"
					disabled={issuerIsSet}
			/>
			<TextField
					id="tokenEndpoint"
					label="Token Endpoint"
					helperText={issuerIsSet && "Disabled when Issuer is set"}
					value={merged["OIDC.TokenEndpoint"] as string}
					onChange={(event) => {setPatch({"OIDC.TokenEndpoint": event.target.value})}}
					margin="normal"
					fullWidth
					variant="outlined"
					disabled={issuerIsSet}
			/>
			<TextField
					id="authorizationEndpoint"
					label="Authorization Endpoint"
					helperText={issuerIsSet && "Disabled when Issuer is set"}
					value={merged["OIDC.AuthorizationEndpoint"] as string}
					onChange={(event) => {setPatch({"OIDC.AuthorizationEndpoint": event.target.value})}}
					margin="normal"
					fullWidth
					variant="outlined"
					disabled={issuerIsSet}
			/>
			<TextField
					id="userInfoEndpoint"
					label="User Info Endpoint"
					helperText={issuerIsSet && "Disabled when Issuer is set"}
					value={merged["OIDC.UserInfoEndpoint"] as string}
					onChange={(event) => {setPatch({"OIDC.UserInfoEndpoint": event.target.value})}}
					margin="normal"
					fullWidth
					variant="outlined"
					disabled={issuerIsSet}
			/>


		</Box>
	</>)
}

export default Page;
