/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

import { Box, Grid, Typography } from '@mui/material';

interface ProgressPagerProps {
  steps: number;
  activeStep: number;
}

interface PagerBoxProps {
  step: number;
  active: boolean;
}

function PagerBox({ step, active }: PagerBoxProps) {
  let backgroundColor = active ? 'primary.main' : 'primary.light';

  return (
    <Box p={2} bgcolor={backgroundColor} borderRadius={2}>
      <Typography>{step + 1}</Typography>
    </Box>
  );
}

export default function ProgressPager({
  steps,
  activeStep,
}: ProgressPagerProps) {
  return (
    <Grid container spacing={1}>
      {Array.from(Array(steps).keys()).map((step) => {
        return (
          <Grid key={step} item>
            <PagerBox step={step} active={step === activeStep} />
          </Grid>
        );
      })}
    </Grid>
  );
}
