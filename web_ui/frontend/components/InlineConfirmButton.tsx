/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

'use client';

// InlineConfirmButton is the text-button equivalent of @chtc/web-components'
// ConfirmButton: the first click swaps the trigger for a small "Confirm? /
// Cancel" pair rather than popping a window.confirm() modal. The label on
// the trigger stays meaningful ("Clear local password", "Clear AUP
// acceptance", etc.), which matters for destructive actions where an
// IconButton is too vague.

import React, { useEffect, useRef, useState } from 'react';
import { Button, ButtonProps, Stack } from '@mui/material';

export interface InlineConfirmButtonProps extends Omit<ButtonProps, 'onClick'> {
  /** Fires on the SECOND click (the explicit "yes, do it" press). */
  onConfirm: () => void;
  /** Optional label for the confirmation button itself. Default: "Confirm". */
  confirmLabel?: string;
  /** Optional label for the cancel button. Default: "Cancel". */
  cancelLabel?: string;
}

const InlineConfirmButton: React.FC<InlineConfirmButtonProps> = ({
  onConfirm,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  children,
  disabled,
  ...buttonProps
}) => {
  const [armed, setArmed] = useState(false);
  const containerRef = useRef<HTMLDivElement | null>(null);

  // Disarm on outside click so the user doesn't leave a "live" confirm
  // button hanging around indefinitely. We don't disarm on Escape — the
  // user can just click elsewhere — but it would be a small extension.
  useEffect(() => {
    if (!armed) return;
    const handler = (ev: MouseEvent) => {
      if (
        containerRef.current &&
        !containerRef.current.contains(ev.target as Node)
      ) {
        setArmed(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [armed]);

  if (armed) {
    return (
      <Stack direction='row' spacing={1} ref={containerRef}>
        <Button
          onClick={() => setArmed(false)}
          disabled={disabled}
          {...buttonProps}
          variant='text'
          color='inherit'
        >
          {cancelLabel}
        </Button>
        <Button
          onClick={() => {
            setArmed(false);
            onConfirm();
          }}
          disabled={disabled}
          {...buttonProps}
          variant='contained'
        >
          {confirmLabel}
        </Button>
      </Stack>
    );
  }
  return (
    <Button {...buttonProps} disabled={disabled} onClick={() => setArmed(true)}>
      {children}
    </Button>
  );
};

export default InlineConfirmButton;
