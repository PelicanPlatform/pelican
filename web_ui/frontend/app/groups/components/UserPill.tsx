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

import React from 'react';
import { Box, Typography } from '@mui/material';
import { UserCard, User } from '@/types';

interface UserPillProps {
  // Either a resolved UserCard (preferred) or a full User (e.g. an existing
  // group member). Pass `id` as a last-resort fallback when only the raw
  // user ID is known.
  card?: UserCard | User | null;
  id?: string;
  /** Optional strong/regular emphasis on the display name. */
  emphasized?: boolean;
}

// formatUserPill formats a user identity as "Display Name (username)".
// Falls back gracefully when displayName is empty (just username) or when
// the user couldn't be resolved at all (raw id, italicized).
export const formatUserPill = (
  card?: UserCard | User | null,
  id?: string
): { primary: string; tone: 'normal' | 'fallback' } => {
  if (card && card.username) {
    if (card.displayName && card.displayName !== card.username) {
      return {
        primary: `${card.displayName} (${card.username})`,
        tone: 'normal',
      };
    }
    return { primary: card.username, tone: 'normal' };
  }
  if (id) return { primary: id, tone: 'fallback' };
  return { primary: '(unset)', tone: 'fallback' };
};

const UserPill: React.FC<UserPillProps> = ({ card, id, emphasized }) => {
  const { primary, tone } = formatUserPill(card, id);
  return (
    <Box component='span'>
      <Typography
        component='span'
        variant='body2'
        sx={{
          fontWeight: emphasized ? 600 : 400,
          fontStyle: tone === 'fallback' ? 'italic' : 'normal',
          color: tone === 'fallback' ? 'text.secondary' : 'text.primary',
          fontFamily: tone === 'fallback' ? 'monospace' : undefined,
          wordBreak: 'break-word',
        }}
      >
        {primary}
      </Typography>
    </Box>
  );
};

export default UserPill;
