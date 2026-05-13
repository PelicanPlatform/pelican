//go:build linux && !ppc64le

/***************************************************************
*
* Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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

package lotman

import (
	"time"

	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/param"
)

// applyCreateLotDefaults fills in MPA fields the caller omitted with the
// same sentinel/derived values that Pelican uses elsewhere (configLotTimestamps,
// the renewal scheduler, schema validators). This keeps the REST surface
// consistent with internally-minted lots: callers only need to supply lot_name
// and paths to get a valid lot.
//
// Defaulting rules (in order):
//   - MPA itself: created if nil.
//   - DedicatedGB: -1.0 (unbounded; the federation budget gates this).
//   - OpportunisticGB: -1.0 (unbounded sentinel).
//   - MaxNumObjects: -1 (unbounded sentinel).
//   - CreationTime: now (in ms since epoch).
//   - ExpirationTime: now + Lotman.DefaultLotExpirationLifetime.
//   - DeletionTime: now + Lotman.DefaultLotDeletionLifetime.
//
// `now` is injected so tests can pin the wall clock and so callers that
// already captured a timestamp upstream get a consistent value across all
// three timestamps.
func applyCreateLotDefaults(req *CreateLotRequest, now time.Time) error {
	if req == nil {
		return errors.New("nil CreateLotRequest")
	}
	if req.MPA == nil {
		req.MPA = &MPA{}
	}
	defaultUnbounded := float64(-1)

	if req.MPA.DedicatedGB == nil {
		v := defaultUnbounded
		req.MPA.DedicatedGB = &v
	}
	if req.MPA.OpportunisticGB == nil {
		v := defaultUnbounded
		req.MPA.OpportunisticGB = &v
	}
	if req.MPA.MaxNumObjects == nil {
		req.MPA.MaxNumObjects = &Int64FromFloat{Value: -1}
	}

	nowMs := now.UnixMilli()
	if req.MPA.CreationTime == nil || req.MPA.CreationTime.Value == 0 {
		req.MPA.CreationTime = &Int64FromFloat{Value: nowMs}
	}
	if req.MPA.ExpirationTime == nil || req.MPA.ExpirationTime.Value == 0 {
		expLife := param.Lotman_DefaultLotExpirationLifetime.GetDuration()
		req.MPA.ExpirationTime = &Int64FromFloat{Value: nowMs + expLife.Milliseconds()}
	}
	if req.MPA.DeletionTime == nil || req.MPA.DeletionTime.Value == 0 {
		delLife := param.Lotman_DefaultLotDeletionLifetime.GetDuration()
		req.MPA.DeletionTime = &Int64FromFloat{Value: nowMs + delLife.Milliseconds()}
	}

	// Sanity: lotman strictly enforces creation < expiration <= deletion.
	if req.MPA.CreationTime.Value >= req.MPA.ExpirationTime.Value {
		return errors.Errorf("creation_time (%d) must be < expiration_time (%d)",
			req.MPA.CreationTime.Value, req.MPA.ExpirationTime.Value)
	}
	if req.MPA.ExpirationTime.Value > req.MPA.DeletionTime.Value {
		return errors.Errorf("expiration_time (%d) must be <= deletion_time (%d)",
			req.MPA.ExpirationTime.Value, req.MPA.DeletionTime.Value)
	}

	return nil
}
