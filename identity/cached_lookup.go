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
	"time"

	"github.com/jellydator/ttlcache/v3"
)

const (
	// DefaultPositiveTTL is the TTL for successful lookups.
	DefaultPositiveTTL = 5 * time.Minute

	// DefaultNegativeTTL is the TTL for failed lookups (shorter to allow
	// recovery when a user/group is created after the first miss).
	DefaultNegativeTTL = 1 * time.Minute

	// lookupTimeout bounds how long a single strategy lookup may take
	// before the cache loader gives up.  This prevents a hung backend
	// (e.g. an unresponsive SSSD socket) from blocking callers indefinitely.
	lookupTimeout = 10 * time.Second
)

// cachedUserResult holds either a successful UserInfo or an error.
type cachedUserResult struct {
	info *UserInfo
	err  error
}

// cachedGIDResult holds either a successful GID or an error.
type cachedGIDResult struct {
	gid uint32
	err error
}

// cachedSecondaryResult holds either a successful secondary GID list or an error.
type cachedSecondaryResult struct {
	gids []uint32
	err  error
}

// CachedLookup wraps a LookupStrategy with a TTL cache for both
// positive and negative lookups.  It implements the Lookup interface
// so it can be used directly by multiuserFileSystem and other consumers.
type CachedLookup struct {
	strategy       LookupStrategy
	minID          uint32
	userCache      *ttlcache.Cache[string, cachedUserResult]
	gidCache       *ttlcache.Cache[string, cachedGIDResult]
	secondaryCache *ttlcache.Cache[string, cachedSecondaryResult]
}

// CachedLookupOption configures a CachedLookup.
type CachedLookupOption func(*CachedLookup)

// WithMinID sets the minimum UID/GID threshold.  Any resolved ID
// below this value will be rejected with ErrBelowMinID.
func WithMinID(minID uint32) CachedLookupOption {
	return func(cl *CachedLookup) {
		cl.minID = minID
	}
}

// NewCachedLookup wraps the given strategy with default TTL caching.
func NewCachedLookup(strategy LookupStrategy, opts ...CachedLookupOption) *CachedLookup {
	return NewCachedLookupWithTTL(strategy, DefaultPositiveTTL, DefaultNegativeTTL, opts...)
}

// NewCachedLookupWithTTL wraps the given strategy with the specified TTLs.
func NewCachedLookupWithTTL(strategy LookupStrategy, positiveTTL, negativeTTL time.Duration, opts ...CachedLookupOption) *CachedLookup {
	cl := &CachedLookup{
		strategy: strategy,
		minID:    DefaultMinID,
	}
	for _, o := range opts {
		o(cl)
	}

	userLoader := ttlcache.LoaderFunc[string, cachedUserResult](
		func(cache *ttlcache.Cache[string, cachedUserResult], username string) *ttlcache.Item[string, cachedUserResult] {
			ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
			defer cancel()
			info, err := strategy.LookupUser(ctx, username)
			result := cachedUserResult{info: info, err: err}
			ttl := positiveTTL
			if err != nil {
				ttl = negativeTTL
			}
			return cache.Set(username, result, ttl)
		},
	)

	gidLoader := ttlcache.LoaderFunc[string, cachedGIDResult](
		func(cache *ttlcache.Cache[string, cachedGIDResult], groupname string) *ttlcache.Item[string, cachedGIDResult] {
			ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
			defer cancel()
			gid, err := strategy.LookupGroup(ctx, groupname)
			result := cachedGIDResult{gid: gid, err: err}
			ttl := positiveTTL
			if err != nil {
				ttl = negativeTTL
			}
			return cache.Set(groupname, result, ttl)
		},
	)

	cl.userCache = ttlcache.New[string, cachedUserResult](
		ttlcache.WithTTL[string, cachedUserResult](positiveTTL),
		ttlcache.WithLoader[string, cachedUserResult](ttlcache.NewSuppressedLoader[string, cachedUserResult](userLoader, nil)),
		ttlcache.WithCapacity[string, cachedUserResult](4096),
	)

	cl.gidCache = ttlcache.New[string, cachedGIDResult](
		ttlcache.WithTTL[string, cachedGIDResult](positiveTTL),
		ttlcache.WithLoader[string, cachedGIDResult](ttlcache.NewSuppressedLoader[string, cachedGIDResult](gidLoader, nil)),
		ttlcache.WithCapacity[string, cachedGIDResult](4096),
	)

	secondaryLoader := ttlcache.LoaderFunc[string, cachedSecondaryResult](
		func(cache *ttlcache.Cache[string, cachedSecondaryResult], username string) *ttlcache.Item[string, cachedSecondaryResult] {
			ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
			defer cancel()
			gids, err := strategy.LookupSecondaryGroups(ctx, username)
			result := cachedSecondaryResult{gids: gids, err: err}
			ttl := positiveTTL
			if err != nil {
				ttl = negativeTTL
			}
			return cache.Set(username, result, ttl)
		},
	)

	cl.secondaryCache = ttlcache.New[string, cachedSecondaryResult](
		ttlcache.WithTTL[string, cachedSecondaryResult](positiveTTL),
		ttlcache.WithLoader[string, cachedSecondaryResult](ttlcache.NewSuppressedLoader[string, cachedSecondaryResult](secondaryLoader, nil)),
		ttlcache.WithCapacity[string, cachedSecondaryResult](4096),
	)

	return cl
}

// UidForUser implements Lookup by looking up the user and returning the UID.
// The cache loader handles both positive and negative (error) entries,
// so Get always returns a non-nil item.
func (c *CachedLookup) UidForUser(username string) (uint32, error) {
	item := c.userCache.Get(username)
	result := item.Value()
	if result.err != nil {
		return 0, result.err
	}
	uid := result.info.UID
	if uid < c.minID {
		return 0, &ErrBelowMinID{Name: username, ID: uid, MinID: c.minID}
	}
	return uid, nil
}

// GidForGroup implements Lookup by delegating to the cached strategy's LookupGroup.
// The cache loader handles both positive and negative (error) entries,
// so Get always returns a non-nil item.
func (c *CachedLookup) GidForGroup(groupname string) (uint32, error) {
	item := c.gidCache.Get(groupname)
	result := item.Value()
	if result.err != nil {
		return 0, result.err
	}
	gid := result.gid
	if gid < c.minID {
		return 0, &ErrBelowMinID{Name: groupname, ID: gid, MinID: c.minID}
	}
	return gid, nil
}

// SecondaryGidsForUser implements Lookup.  It returns the secondary GIDs
// for the given username, filtering out any GID below the minimum threshold.
// The cache loader handles both positive and negative (error) entries,
// so Get always returns a non-nil item.
func (c *CachedLookup) SecondaryGidsForUser(username string) ([]uint32, error) {
	item := c.secondaryCache.Get(username)
	result := item.Value()
	if result.err != nil {
		return nil, result.err
	}

	// Filter out GIDs below the minimum threshold.
	var filtered []uint32
	for _, gid := range result.gids {
		if gid >= c.minID {
			filtered = append(filtered, gid)
		}
	}
	return filtered, nil
}

// Name returns the name of the underlying strategy.
func (c *CachedLookup) Name() string {
	return c.strategy.Name()
}
