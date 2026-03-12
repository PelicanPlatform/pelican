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

package identity

import (
	"context"
	"errors"
)

// ChainedLookupStrategy tries multiple strategies in order until one succeeds.
type ChainedLookupStrategy struct {
	strategies []LookupStrategy
}

// LookupUser tries each strategy in order.  ErrUserNotFound causes a
// fallthrough to the next strategy; other errors also fall through.
func (c *ChainedLookupStrategy) LookupUser(ctx context.Context, username string) (*UserInfo, error) {
	var lastErr error
	for _, s := range c.strategies {
		info, err := s.LookupUser(ctx, username)
		if err == nil {
			return info, nil
		}
		lastErr = err
		// Always try next strategy
		var notFound *ErrUserNotFound
		if !errors.As(err, &notFound) {
			continue
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, &ErrUserNotFound{Username: username}
}

// LookupSecondaryGroups tries each strategy in order.
func (c *ChainedLookupStrategy) LookupSecondaryGroups(ctx context.Context, username string) ([]uint32, error) {
	var lastErr error
	for _, s := range c.strategies {
		gids, err := s.LookupSecondaryGroups(ctx, username)
		if err == nil {
			return gids, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, &ErrUserNotFound{Username: username}
}

// LookupGroup tries each strategy in order.
func (c *ChainedLookupStrategy) LookupGroup(ctx context.Context, groupname string) (uint32, error) {
	var lastErr error
	for _, s := range c.strategies {
		gid, err := s.LookupGroup(ctx, groupname)
		if err == nil {
			return gid, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return 0, lastErr
	}
	return 0, &ErrGroupNotFound{Groupname: groupname}
}

// Name returns the names of all strategies in the chain.
func (c *ChainedLookupStrategy) Name() string {
	if len(c.strategies) == 0 {
		return "chained-empty"
	}
	name := "chained:"
	for i, s := range c.strategies {
		if i > 0 {
			name += ","
		}
		name += s.Name()
	}
	return name
}
