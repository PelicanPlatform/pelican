//go:build !windows

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

package director

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

func TestForwardService(t *testing.T) {
	directorNameOnce = sync.Once{}
	directorName = ""
	directorNameError = nil

	viper.Set(param.Director_AdvertiseUrl.GetName(), "http://director-ad-url")
	defer viper.Set(param.Director_AdvertiseUrl.GetName(), "")
	viper.Set(param.Server_ExternalWebUrl.GetName(), "http://external-url")
	defer viper.Set(param.Server_ExternalWebUrl.GetName(), "")

	ctx := context.Background()
	ad := &server_structs.OriginAdvertiseV2{
		ServerBaseAd: server_structs.ServerBaseAd{
			Name:         "svc-name",
			InstanceID:   "inst-id",
			StartTime:    12345,
			GenerationID: 1,
			Version:      "v1",
			Expiration:   time.Unix(67890, 0).UTC(),
		},
		DataURL: "http://data-url",
	}

	ch := make(chan *forwardAdInfo, 1)
	dir := &directorInfo{forwardAdChan: ch}

	dir.forwardService(ctx, ad, server_structs.OriginType)

	info := <-ch
	assert.Equal(t, ad.Name, info.key)
	assert.Equal(t, server_structs.OriginType, info.adType)
	assert.Equal(t, ad.Name, info.serverBase.Name)
	assert.Equal(t, ad.InstanceID, info.serverBase.InstanceID)
	assert.Equal(t, ad.StartTime, info.serverBase.StartTime)
	assert.Equal(t, ad.GenerationID, info.serverBase.GenerationID)
	assert.Equal(t, ad.Version, info.serverBase.Version)
	assert.Equal(t, ad.Expiration, info.serverBase.Expiration)

	data, err := io.ReadAll(info.contents)
	require.NoError(t, err)

	var fwd ForwardAd
	require.NoError(t, json.Unmarshal(data, &fwd))
	assert.Equal(t, viper.GetString(param.Director_AdvertiseUrl.GetName()), fwd.DirectorAd.AdvertiseUrl)
	assert.Equal(t, server_structs.OriginType.String(), fwd.AdType)
	assert.False(t, fwd.Now.IsZero())
	assert.Equal(t, ad, fwd.ServiceAd)
}

// TestForwardServiceAd tests that we forward the service ad to the correct director
// We have two directors, each with different advertise urls
// We have a service ad that should be only forwarded to the director that is not itself
func TestForwardServiceAd(t *testing.T) {
	viper.Set(param.Server_ExternalWebUrl.GetName(), "http://director1.com")
	defer viper.Set(param.Server_ExternalWebUrl.GetName(), "")

	// Reset the cache
	directorAds.DeleteAll()

	ch1 := make(chan *forwardAdInfo, 1)
	dir1 := &directorInfo{
		ad: &server_structs.DirectorAd{
			AdvertiseUrl: "http://director-ad-url-1",
			ServerBaseAd: server_structs.ServerBaseAd{
				Name:         "dir1",
				InstanceID:   "inst-id-1",
				StartTime:    12345,
				GenerationID: 1,
				Version:      "v1",
			},
		},
		forwardAdChan: ch1,
	}

	ch2 := make(chan *forwardAdInfo, 1)
	dir2 := &directorInfo{
		ad: &server_structs.DirectorAd{
			AdvertiseUrl: "http://director-ad-url-2",
			ServerBaseAd: server_structs.ServerBaseAd{
				Name:         "dir2",
				InstanceID:   "inst-id-2",
				StartTime:    12345,
				GenerationID: 1,
				Version:      "v1",
			},
		},
		forwardAdChan: ch2,
	}

	directorAds.Set("dir1", dir1, 15*time.Minute)
	directorAds.Set("dir2", dir2, 15*time.Minute)

	// Build a fake service ad
	svcAd := &server_structs.OriginAdvertiseV2{
		ServerBaseAd: server_structs.ServerBaseAd{
			Name:         "svc-name",
			InstanceID:   "inst-id",
			StartTime:    12345,
			GenerationID: 1,
			Version:      "v1",
			Expiration:   time.Unix(67890, 0).UTC(),
		},
	}

	ctx := context.Background()
	forwardServiceAd(ctx, svcAd, server_structs.OriginType, dir1.ad)

	// We should have received an ad on channel 2 but not channel 1
	select {
	case adInfo := <-ch1:
		assert.Fail(t, "Received an ad on channel 1 but it should have been skipped", adInfo.serverBase)
	default:
	}

	select {
	case adInfo := <-ch2: // We should have received an ad on channel 2
		assert.Equal(t, svcAd.ServerBaseAd, adInfo.serverBase)
	default:
		assert.Fail(t, "Failed to receive an ad on channel 2")
	}
}
