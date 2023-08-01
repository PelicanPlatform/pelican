import {Box, Grid, Typography} from "@mui/material";

interface ProgressPagerProps {
    steps: number;
    activeStep: number;
}

interface PagerBoxProps {
    step: number;
    active: boolean;
}

function PagerBox({step, active}: PagerBoxProps) {

    let backgroundColor = active ? "primary.main" : "primary.light"

    return (
        <Box p={2} bgcolor={backgroundColor} borderRadius={2}>
            <Typography>{step + 1}</Typography>
        </Box>
    )
}

export default function ProgressPager({steps, activeStep}: ProgressPagerProps) {
    return (
        <Grid container spacing={1}>
            {
                Array.from(Array(steps).keys()).map((step) => {
                    return (
                        <Grid key={step} item>
                            <PagerBox step={step} active={step === activeStep}/>
                        </Grid>
                    )
                })
            }
        </Grid>
    )
}