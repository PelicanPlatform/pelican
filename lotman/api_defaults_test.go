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
	req := &CreateLotRequest{
		LotName: "test",
		Paths:   []LotPath{{Path: "/foo", Recursive: true}},
	}
	require.NoError(t, applyCreateLotDefaults(req, now))

	require.NotNil(t, req.MPA)
	require.NotNil(t, req.MPA.DedicatedGB)
	assert.Equal(t, float64(-1), *req.MPA.DedicatedGB, "DedicatedGB should default to -1 sentinel")
	require.NotNil(t, req.MPA.OpportunisticGB)
	assert.Equal(t, float64(-1), *req.MPA.OpportunisticGB, "OpportunisticGB should default to -1 sentinel")
	require.NotNil(t, req.MPA.MaxNumObjects)
	assert.Equal(t, int64(-1), req.MPA.MaxNumObjects.Value, "MaxNumObjects should default to -1 sentinel")

	require.NotNil(t, req.MPA.CreationTime)
	assert.Equal(t, now.UnixMilli(), req.MPA.CreationTime.Value)
	require.NotNil(t, req.MPA.ExpirationTime)
	assert.Equal(t, now.UnixMilli()+(168*time.Hour).Milliseconds(), req.MPA.ExpirationTime.Value)
	require.NotNil(t, req.MPA.DeletionTime)
	assert.Equal(t, now.UnixMilli()+(336*time.Hour).Milliseconds(), req.MPA.DeletionTime.Value)
}

func TestApplyCreateLotDefaults_PreservesCallerProvidedValues(t *testing.T) {
	resetForDefaults(t)

	ded := float64(42)
	opp := float64(7)
	req := &CreateLotRequest{
		LotName: "test",
		Paths:   []LotPath{{Path: "/foo"}},
		MPA: &MPA{
			DedicatedGB:     &ded,
			OpportunisticGB: &opp,
			MaxNumObjects:   &Int64FromFloat{Value: 100},
			CreationTime:    &Int64FromFloat{Value: 1000},
			ExpirationTime:  &Int64FromFloat{Value: 2000},
			DeletionTime:    &Int64FromFloat{Value: 3000},
		},
	}
	require.NoError(t, applyCreateLotDefaults(req, time.Now()))

	assert.Equal(t, float64(42), *req.MPA.DedicatedGB)
	assert.Equal(t, float64(7), *req.MPA.OpportunisticGB)
	assert.Equal(t, int64(100), req.MPA.MaxNumObjects.Value)
	assert.Equal(t, int64(1000), req.MPA.CreationTime.Value)
	assert.Equal(t, int64(2000), req.MPA.ExpirationTime.Value)
	assert.Equal(t, int64(3000), req.MPA.DeletionTime.Value)
}

func TestApplyCreateLotDefaults_RejectsBadOrdering(t *testing.T) {
	resetForDefaults(t)

	t.Run("creation >= expiration", func(t *testing.T) {
		req := &CreateLotRequest{
			LotName: "test",
			Paths:   []LotPath{{Path: "/foo"}},
			MPA: &MPA{
				CreationTime:   &Int64FromFloat{Value: 5000},
				ExpirationTime: &Int64FromFloat{Value: 5000},
				DeletionTime:   &Int64FromFloat{Value: 6000},
			},
		}
		err := applyCreateLotDefaults(req, time.Now())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "creation_time")
	})

	t.Run("expiration > deletion", func(t *testing.T) {
		req := &CreateLotRequest{
			LotName: "test",
			Paths:   []LotPath{{Path: "/foo"}},
			MPA: &MPA{
				CreationTime:   &Int64FromFloat{Value: 1000},
				ExpirationTime: &Int64FromFloat{Value: 5000},
				DeletionTime:   &Int64FromFloat{Value: 4000},
			},
		}
		err := applyCreateLotDefaults(req, time.Now())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expiration_time")
	})
}

func TestApplyCreateLotDefaults_OverridesZeroTimestamps(t *testing.T) {
	resetForDefaults(t)
	now := time.Unix(1_700_000_000, 0)
	zero := Int64FromFloat{Value: 0}
	req := &CreateLotRequest{
		LotName: "test",
		Paths:   []LotPath{{Path: "/foo"}},
		MPA: &MPA{
			CreationTime:   &zero,
			ExpirationTime: &zero,
			DeletionTime:   &zero,
		},
	}
	require.NoError(t, applyCreateLotDefaults(req, now))
	assert.NotEqual(t, int64(0), req.MPA.CreationTime.Value)
	assert.NotEqual(t, int64(0), req.MPA.ExpirationTime.Value)
	assert.NotEqual(t, int64(0), req.MPA.DeletionTime.Value)
}
