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

package lotman

import (
	"time"

	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/param"
)

// applyCreateLotDefaults validates required fields on a CreateLotRequest and
// fills in the timestamp / opportunistic / max-objects fields the caller
// omitted. The dedicated-GB quota is intentionally NOT defaulted: a
// reservation without an explicit size budget would either be unbounded
// (dangerous, since lotman gives away the whole federation budget by
// default) or zero-sized (useless), so neither is a reasonable default.
//
// Defaulting rules (in order):
//   - ManagementPolicyAttrs (alias MPA): MUST be supplied. DedicatedGB
//     within it MUST also be supplied; an error is returned otherwise.
//   - OpportunisticGB: -1.0 (unbounded sentinel) when omitted.
//   - MaxNumObjects: -1 (unbounded sentinel) when omitted.
//   - CreationTimeMs: now when omitted or zero.
//   - ExpirationTimeMs: now + Lotman.DefaultLotExpirationLifetime when omitted or zero.
//   - DeletionTimeMs: now + Lotman.DefaultLotDeletionLifetime when omitted or zero.
//
// `now` is injected so tests can pin the wall clock and so callers that
// already captured a timestamp upstream get a consistent value across all
// three timestamps.
func applyCreateLotDefaults(req *CreateLotRequest, now time.Time) error {
	if req == nil {
		return errors.New("nil CreateLotRequest")
	}
	if req.ManagementPolicyAttrs == nil {
		return errors.New("managementPolicyAttrs is required")
	}
	mpa := req.ManagementPolicyAttrs
	if mpa.DedicatedGB == nil {
		return errors.New("managementPolicyAttrs.dedicatedGB is required")
	}
	defaultUnbounded := float64(-1)

	if mpa.OpportunisticGB == nil {
		v := defaultUnbounded
		mpa.OpportunisticGB = &v
	}
	if mpa.MaxNumObjects == nil {
		v := int64(-1)
		mpa.MaxNumObjects = &v
	}

	nowMs := now.UnixMilli()
	if mpa.CreationTimeMs == nil || *mpa.CreationTimeMs == 0 {
		v := nowMs
		mpa.CreationTimeMs = &v
	}
	if mpa.ExpirationTimeMs == nil || *mpa.ExpirationTimeMs == 0 {
		expLife := param.Lotman_DefaultLotExpirationLifetime.GetDuration()
		v := nowMs + expLife.Milliseconds()
		mpa.ExpirationTimeMs = &v
	}
	if mpa.DeletionTimeMs == nil || *mpa.DeletionTimeMs == 0 {
		delLife := param.Lotman_DefaultLotDeletionLifetime.GetDuration()
		v := nowMs + delLife.Milliseconds()
		mpa.DeletionTimeMs = &v
	}

	// Sanity: lotman strictly enforces creation < expiration <= deletion.
	if *mpa.CreationTimeMs >= *mpa.ExpirationTimeMs {
		return errors.Errorf("creationTimeMs (%d) must be < expirationTimeMs (%d)",
			*mpa.CreationTimeMs, *mpa.ExpirationTimeMs)
	}
	if *mpa.ExpirationTimeMs > *mpa.DeletionTimeMs {
		return errors.Errorf("expirationTimeMs (%d) must be <= deletionTimeMs (%d)",
			*mpa.ExpirationTimeMs, *mpa.DeletionTimeMs)
	}

	return nil
}
