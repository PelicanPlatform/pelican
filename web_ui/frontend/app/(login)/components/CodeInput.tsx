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

import { ChangeEvent, ClipboardEvent, KeyboardEvent, useRef } from 'react';
import { Grid, TextField } from '@mui/material';

export type Code = (number | undefined)[];

interface CodeInputProps {
  length: number;
  setCode: (code: Code) => void;
  submitFunction?: () => void;
}

export default function CodeInput({
  length,
  setCode,
  submitFunction,
}: CodeInputProps) {
  const inputRefs = useRef<HTMLInputElement[] | null[] | never[]>([]);

  /**
   * Set the code in the input blocks
   * @param code
   * @param offset
   */
  function setInputs(code: number[], offset: number) {
    if (code.length == length) {
      offset = 0;
    }

    Array.from(Array(code.length).keys()).forEach((index) => {
      if (index + offset < inputRefs.current.length) {
        inputRefs.current[index + offset]!.value = code[index].toString();
      }
    });

    // Set the code
    setCode(getValue());
  }

  /**
   * Get the value of the input blocks
   */
  function getValue(): Code {
    return inputRefs.current.map((input) => {
      return input!.value == '' ? undefined : Number(input!.value);
    });
  }

  /**
   * Handle change in one of the input blocks
   * - Checks that the input is an integer
   * @param e
   * @param index
   */
  const onChange = (e: ChangeEvent, index: number) => {
    // Check that the input was a legal one
    const currentInput = inputRefs.current[index];
    if (!Number.isInteger(Number(currentInput!.value))) {
      currentInput!.value = '';
      return;
    }

    // Set the code
    setCode(getValue());

    // If the current input is not the last advance focus
    if (index != inputRefs.current.length - 1) {
      const nextInput = inputRefs.current[index + 1];
      nextInput!.focus();
    }
  };

  /**
   * Handle pasting into one of the input blocks
   *
   * Maps a ClipboardEvent to setCode function
   *
   * @param e
   * @param index: Index of the input block event was captured in
   */
  const onPaste = (e: ClipboardEvent, index: number) => {
    let code = e.clipboardData
      .getData('Text')
      .split('')
      .map((x) => Number(x));

    setInputs(code, index);
  };

  /**
   * Handle backspace in one of the input blocks
   * @param e
   * @param index: Index of the input block event was captured in
   */
  const onKeyDown = (e: KeyboardEvent, index: number) => {
    if (['Backspace'].includes(e.code)) {
      const currentInput = inputRefs.current[index];

      // If the current input is the first one, clear it
      if (index == 0) {
        currentInput!.value = '';
      } else {
        const previousInput = inputRefs.current[index - 1];

        // If the current input is empty, focus the previous one
        if (currentInput!.value == '') {
          previousInput!.focus();

          // Empty the current input
        } else {
          currentInput!.value = '';
        }
      }
      e.preventDefault();
    }
  };

  return (
    <Grid container spacing={1}>
      {Array.from(Array(length).keys()).map((index) => {
        return (
          <Grid item key={index} textAlign={'center'}>
            <TextField
              inputProps={{
                sx: {
                  width: { xs: '30px', md: '50px' },
                  borderWidth: '3px',
                  fontSize: { xs: '1.8rem', md: '3rem' },
                  textAlign: 'center',
                  padding: '.5rem',
                  backgroundColor: 'secondary.main',
                },
                maxLength: 1,
                ref: (el: HTMLInputElement) => (inputRefs.current[index] = el),
              }}
              variant='outlined'
              onKeyDown={(e) => onKeyDown(e, index)}
              onChange={(e) => onChange(e, index)}
              onPaste={(e) => onPaste(e, index)}
            />
          </Grid>
        );
      })}
    </Grid>
  );
}
