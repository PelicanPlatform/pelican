import {Typography} from "@mui/material";

const Page = () => {

	return (<>
		<Typography variant={"subtitle1"} component={"h2"} gutterBottom>
			User Authorization Configuration
		</Typography>
		<Typography variant={"body1"} gutterBottom>
			This set of configuration defines the permissions allowed to authenticated users.
		</Typography>
		<Typography variant={"body2"} gutterBottom>
			Using the previous configuration Pelican with authenticate a user and verify their identity with the OpenID
			Connect provider. Once we have their identity, the rules below will determine what actions this identity is
			authorized to perform.
		</Typography>

	</>)
}

export default Page;
