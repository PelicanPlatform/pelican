'use client'

import {ReactElement, useCallback, useContext, useMemo} from "react";
import {ConfigurationContext} from "@/components/ConfigurationProvider/ConfigurationProvider";
import {usePathname} from "next/navigation";
import {Box, Button, Step, StepLabel, Stepper, Typography} from "@mui/material";
import Link from "next/link";
import CircularProgress from "@mui/material/CircularProgress";

const steps = [
	"Client",
	"Provider",
	"Authorization",
	"Advanced"
]

const IssuerFlowContainer = ({children}: {children: ReactElement}) => {

	const {submit, submitting} = useContext(ConfigurationContext)


	// Get current location in the form
	const url = usePathname()
	const activeIndex = useMemo(() => {
		return steps.findIndex((step) => step.toLowerCase() == url.split("/").at(-2))
	}, [url])

	// Get the previous step
	const previousStep = useMemo(() => {
		return steps[activeIndex - 1]
	}, [activeIndex])

	// Get the next step
	const nextStep = useMemo(() => {
		return steps[activeIndex + 1]
	}, [activeIndex])

	const submitAndContinue = useCallback(async (e: {preventDefault: () => void}) => {
		if (submitting) return;
		const success = await submit();
		if(!success) {
			e.preventDefault();
		}
	}, [submitting, submit])

	return (
			<Box
					sx={{
						maxWidth: "80ch"
					}}
			>
				<Typography variant={"h4"} component={"h1"}>
					Origin Issuer Setup
				</Typography>
				{children}
				<Box display={"flex"} justifyContent={"space-between"} mt={2} mb={2}>
					<Box>
						{activeIndex > 0 && (
								<Link href={`../${previousStep.toLowerCase()}/`} passHref>
									<Button variant={"outlined"}>Previous</Button>
								</Link>
						)}
					</Box>
					<Box>
						{activeIndex < steps.length - 1 && (
								<Link href={`../${nextStep.toLowerCase()}/`} onNavigate={(e) => submitAndContinue(e)}>
									<Button variant={"contained"}>
										{submitting ? (
												<CircularProgress />
										) : (
												<>Next</>
										)}
									</Button>
								</Link>
						)}
						{activeIndex == steps.length - 1 && (
								<Link href={"../../"} onNavigate={(e) => submitAndContinue(e)}>
									<Button variant={"contained"}>Finish</Button>
								</Link>
						)}
					</Box>
				</Box>
				<Stepper>
					{steps.map((label, index) => {

						return (
								<Step key={label} active={index == activeIndex} completed={index < activeIndex}>
									<StepLabel>{label}</StepLabel>
								</Step>
						)
					})}
				</Stepper>
			</Box>
	)
}

export default IssuerFlowContainer;
