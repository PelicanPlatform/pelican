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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

// resetForDefaults restores the duration params used by applyCreateLotDefaults
// after each test. Tests that need to vary these values do so locally and then
// rely on this t.Cleanup to put things back.
func resetForDefaults(t *testing.T) {
	t.Helper()
	require.NoError(t, param.Lotman_DefaultLotExpirationLifetime.Set(168*time.Hour))
	require.NoError(t, param.Lotman_DefaultLotDeletionLifetime.Set(336*time.Hour))
	t.Cleanup(server_utils.ResetTestState)
}

func TestApplyCreateLotDefaults_NilRequest(t *testing.T) {
	require.Error(t, applyCreateLotDefaults(nil, time.Now()))
}

func TestApplyCreateLotDefaults_FillsAllOmittedFields(t *testing.T) {
	resetForDefaults(t)

	now := time.Unix(1_700_000_000, 0)
	ded := float64(5)
	req := &CreateLotRequest{
		LotName:               "test",
		Paths:                 []LotPathInput{{Path: "/foo", Recursive: true}},
		ManagementPolicyAttrs: &MPAInput{DedicatedGB: &ded},
	}
	require.NoError(t, applyCreateLotDefaults(req, now))

	mpa := req.ManagementPolicyAttrs
	require.NotNil(t, mpa)
	require.NotNil(t, mpa.DedicatedGB)
	assert.Equal(t, float64(5), *mpa.DedicatedGB, "caller-supplied DedicatedGB is preserved")
	require.NotNil(t, mpa.OpportunisticGB)
	assert.Equal(t, float64(-1), *mpa.OpportunisticGB, "OpportunisticGB should default to -1 sentinel")
	require.NotNil(t, mpa.MaxNumObjects)
	assert.Equal(t, int64(-1), *mpa.MaxNumObjects, "MaxNumObjects should default to -1 sentinel")

	require.NotNil(t, mpa.CreationTimeMs)
	assert.Equal(t, now.UnixMilli(), *mpa.CreationTimeMs)
	require.NotNil(t, mpa.ExpirationTimeMs)
	assert.Equal(t, now.UnixMilli()+(168*time.Hour).Milliseconds(), *mpa.ExpirationTimeMs)
	require.NotNil(t, mpa.DeletionTimeMs)
	assert.Equal(t, now.UnixMilli()+(336*time.Hour).Milliseconds(), *mpa.DeletionTimeMs)
}

func TestApplyCreateLotDefaults_RequiresManagementPolicyAttrs(t *testing.T) {
	resetForDefaults(t)
	req := &CreateLotRequest{
		LotName: "test",
		Paths:   []LotPathInput{{Path: "/foo"}},
	}
	err := applyCreateLotDefaults(req, time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "managementPolicyAttrs")
}

func TestApplyCreateLotDefaults_RequiresDedicatedGB(t *testing.T) {
	resetForDefaults(t)
	req := &CreateLotRequest{
		LotName:               "test",
		Paths:                 []LotPathInput{{Path: "/foo"}},
		ManagementPolicyAttrs: &MPAInput{},
	}
	err := applyCreateLotDefaults(req, time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dedicatedGB")
}

func TestApplyCreateLotDefaults_PreservesCallerProvidedValues(t *testing.T) {
	resetForDefaults(t)

	ded := float64(42)
	opp := float64(7)
	maxObj := int64(100)
	creation := int64(1000)
	expiration := int64(2000)
	deletion := int64(3000)
	req := &CreateLotRequest{
		LotName: "test",
		Paths:   []LotPathInput{{Path: "/foo"}},
		ManagementPolicyAttrs: &MPAInput{
			DedicatedGB:      &ded,
			OpportunisticGB:  &opp,
			MaxNumObjects:    &maxObj,
			CreationTimeMs:   &creation,
			ExpirationTimeMs: &expiration,
			DeletionTimeMs:   &deletion,
		},
	}
	require.NoError(t, applyCreateLotDefaults(req, time.Now()))

	mpa := req.ManagementPolicyAttrs
	assert.Equal(t, float64(42), *mpa.DedicatedGB)
	assert.Equal(t, float64(7), *mpa.OpportunisticGB)
	assert.Equal(t, int64(100), *mpa.MaxNumObjects)
	assert.Equal(t, int64(1000), *mpa.CreationTimeMs)
	assert.Equal(t, int64(2000), *mpa.ExpirationTimeMs)
	assert.Equal(t, int64(3000), *mpa.DeletionTimeMs)
}

func TestApplyCreateLotDefaults_RejectsBadOrdering(t *testing.T) {
	resetForDefaults(t)
	ded := float64(1)

	t.Run("creation >= expiration", func(t *testing.T) {
		creation := int64(5000)
		expiration := int64(5000)
		deletion := int64(6000)
		req := &CreateLotRequest{
			LotName: "test",
			Paths:   []LotPathInput{{Path: "/foo"}},
			ManagementPolicyAttrs: &MPAInput{
				DedicatedGB:      &ded,
				CreationTimeMs:   &creation,
				ExpirationTimeMs: &expiration,
				DeletionTimeMs:   &deletion,
			},
		}
		err := applyCreateLotDefaults(req, time.Now())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "creationTimeMs")
	})

	t.Run("expiration > deletion", func(t *testing.T) {
		creation := int64(1000)
		expiration := int64(5000)
		deletion := int64(4000)
		req := &CreateLotRequest{
			LotName: "test",
			Paths:   []LotPathInput{{Path: "/foo"}},
			ManagementPolicyAttrs: &MPAInput{
				DedicatedGB:      &ded,
				CreationTimeMs:   &creation,
				ExpirationTimeMs: &expiration,
				DeletionTimeMs:   &deletion,
			},
		}
		err := applyCreateLotDefaults(req, time.Now())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expirationTimeMs")
	})
}

func TestApplyCreateLotDefaults_OverridesZeroTimestamps(t *testing.T) {
	resetForDefaults(t)
	now := time.Unix(1_700_000_000, 0)
	ded := float64(1)
	zero := int64(0)
	req := &CreateLotRequest{
		LotName: "test",
		Paths:   []LotPathInput{{Path: "/foo"}},
		ManagementPolicyAttrs: &MPAInput{
			DedicatedGB:      &ded,
			CreationTimeMs:   &zero,
			ExpirationTimeMs: &zero,
			DeletionTimeMs:   &zero,
		},
	}
	require.NoError(t, applyCreateLotDefaults(req, now))
	mpa := req.ManagementPolicyAttrs
	assert.NotEqual(t, int64(0), *mpa.CreationTimeMs)
	assert.NotEqual(t, int64(0), *mpa.ExpirationTimeMs)
	assert.NotEqual(t, int64(0), *mpa.DeletionTimeMs)
}
