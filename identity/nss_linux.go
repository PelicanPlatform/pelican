//go:build linux && !cgo

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
	"sync"
	"time"
)

// NSSLookupStrategy uses nsswitch.conf to determine the order of lookup
// strategies then chains them together.
type NSSLookupStrategy struct {
	*ChainedLookupStrategy
}

var (
	nssInitOnce   sync.Once
	nssMethods    []NSSSwitchMethod
	nssParseErr   error
	nssSwitchPath = "/etc/nsswitch.conf"
)

// ResetNSSCache resets the nsswitch.conf parsing cache (for testing).
func ResetNSSCache() {
	nssInitOnce = sync.Once{}
	nssMethods = nil
	nssParseErr = nil
}

// SetNSSSwitchPath sets the path to nsswitch.conf (for testing).
// Must be called before NewNSSLookup and after ResetNSSCache.
func SetNSSSwitchPath(path string) {
	nssSwitchPath = path
}

// NewNSSLookup creates an NSS-based lookup strategy by parsing
// nsswitch.conf and chaining the corresponding backends.
func NewNSSLookup() (*NSSLookupStrategy, error) {
	nssInitOnce.Do(func() {
		nssMethods, nssParseErr = ParseNSSwitch(nssSwitchPath)
	})

	if nssParseErr != nil {
		return nil, nssParseErr
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var strategies []LookupStrategy
	for _, method := range nssMethods {
		switch method {
		case NSSSwitchMethodSSS:
			if s, err := trySSSD(ctx); err == nil && s != nil {
				strategies = append(strategies, s)
			}
		case NSSSwitchMethodFiles:
			if s, err := tryGoFallback(); err == nil && s != nil {
				strategies = append(strategies, s)
			}
		}
	}

	if len(strategies) == 0 {
		return nil, ErrStrategyNotAvailable
	}

	return &NSSLookupStrategy{
		ChainedLookupStrategy: &ChainedLookupStrategy{strategies: strategies},
	}, nil
}

// Name returns the strategy name.
func (n *NSSLookupStrategy) Name() string {
	return "nss:" + n.ChainedLookupStrategy.Name()
}

// tryNSSStrategy attempts to create an NSS-based lookup strategy.
func tryNSSStrategy() (LookupStrategy, error) {
	return NewNSSLookup()
}
