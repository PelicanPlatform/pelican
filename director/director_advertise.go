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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/jellydator/ttlcache/v3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/version"
)

// Server routines for managing the known directors

type (
	// Helper structure for recording both the advertising token and its expiration
	advertiseToken struct {
		token  string
		expiry time.Time
	}

	// Structure representing a remote director and the
	// channel to interact with the corresponding goroutine
	directorInfo struct {
		ad             *server_structs.DirectorAd
		forwardAdChan  chan *forwardAdInfo // Channel for ads for forwarding from the director handler to the internal buffer
		internalAdChan chan *forwardAdInfo // Channel for ads from the internal buffer to the HTTP client forwarder goroutine.
		cancel         context.CancelFunc
		token          advertiseToken
	}

	// Information needed to forward an ad to a remote director
	forwardAdInfo struct {
		key        string
		adType     server_structs.ServerType
		contents   *bytes.Buffer
		serverBase server_structs.ServerBaseAd
	}

	// Wire representation of a forwarded ad
	//
	// We provided both the director that produced the ad and the
	// ad itself.  Having the director ad helps detect forwarding
	// loops -- we can break early if we detect we're talking to ourself!
	forwardAd struct {
		DirectorAd *server_structs.DirectorAd        `json:"director-ad"`
		AdType     string                            `json:"ad-type"`
		Now        time.Time                         `json:"now"`
		ServiceAd  *server_structs.OriginAdvertiseV2 `json:"service-ad,omitempty"`
	}
)

var (
	directorAds = ttlcache.New(
		ttlcache.WithTTL[string, *directorInfo](15*time.Minute),
		ttlcache.WithDisableTouchOnHit[string, *directorInfo](),
	)
	directorAdMutex = sync.RWMutex{}

	// Determine the name of the director; only done once
	directorNameOnce  sync.Once
	directorName      string
	directorNameError error
)

// List all the directors known to this instance
func listDirectors(ctx *gin.Context) {
	ads := make([]server_structs.DirectorAd, 0, directorAds.Len())
	func() {
		directorAdMutex.RLock()
		defer directorAdMutex.RUnlock()
		// If we are bootstrapping, we might not have gotten any director ads yet -- not even
		// our own!  In that case, pull some from the server_utils routine other modules use.
		if directorAds.Len() == 0 {
			ads = server_utils.GetDirectorAds()
		} else {
			directorAds.Range(func(item *ttlcache.Item[string, *directorInfo]) bool {
				if item.Value() != nil && item.Value().ad != nil {
					ads = append(ads, *item.Value().ad)
				}
				return true
			})
		}
	}()
	ctx.JSON(http.StatusOK, ads)
}

// Handle API call that registers the director ad from a remote client
func registerDirectorAd(appCtx context.Context, egrp *errgroup.Group, ctx *gin.Context) {
	status, ok, err := token.Verify(ctx, token.AuthOption{
		Sources: []token.TokenSource{token.Header},
		Issuers: []token.TokenIssuer{token.FederationIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.Pelican_DirectorAdvertise},
	})
	if !ok || err != nil {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprint("Failed to verify the token: ", err),
		})
		return
	}

	// copy the body to a new buffer so we can debug it
	body, _ := io.ReadAll(ctx.Request.Body)
	fmt.Printf("Received body: %+v\n", string(body))

	// reset the body
	ctx.Request.Body = io.NopCloser(bytes.NewBuffer(body))

	fAd := forwardAd{}
	if err = ctx.MustBindWith(&fAd, binding.JSON); err != nil {
		log.Errorln("Failed to bind JSON:", err)
		return
	}
	directorAd := fAd.DirectorAd

	// Reset the expiration times if we detect significant skew between the claimed time sent
	// and the current time.
	//
	// That is, if the ad claims to have been sent at noon and expiring at 12:15 but the server
	// received it at 13:00, then assume the expiration time is 13:15 (since the original lifetime
	// was set to 15 minutes).
	now := time.Now()
	if skew := now.Sub(fAd.Now); skew > 100*time.Millisecond || skew < -100*time.Millisecond {
		if fAd.DirectorAd != nil {
			lifetime := fAd.DirectorAd.Expiration.Sub(fAd.Now)
			if lifetime > 0 {
				fAd.DirectorAd.Expiration = now.Add(lifetime)
			}
		}
		if fAd.ServiceAd != nil {
			lifetime := fAd.ServiceAd.Expiration.Sub(fAd.Now)
			if lifetime > 0 {
				fAd.ServiceAd.Expiration = now.Add(lifetime)
			}
		}
	}

	if fAd.AdType == server_structs.DirectorType.String() {
		if directorAd.Name != "" {
			func() {
				directorAdMutex.Lock()
				defer directorAdMutex.Unlock()
				updateInternalDirectorCache(ctx, egrp, directorAd)
			}()
		}
	} else if fAd.AdType == server_structs.CacheType.String() || fAd.AdType == server_structs.OriginType.String() {
		if fAd.ServiceAd == nil {
			log.Debugln("Received registration of type", fAd.AdType, "with missing service ad")
			ctx.AbortWithStatusJSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Bad request. Service ad is missing in forward request",
			})
			return
		}
		sType := server_structs.CacheType
		if fAd.AdType == server_structs.OriginType.String() {
			sType = server_structs.OriginType
		}
		finishRegisterServeAd(appCtx, ctx, fAd.ServiceAd, sType)
		if ctx.IsAborted() {
			return
		}

		forwardServiceAd(appCtx, fAd.ServiceAd, sType)

	} else {
		log.Debugln("Received registration of unrecognized type", fAd.AdType)
		ctx.AbortWithStatusJSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Bad request. Invalid ad type for forwarding",
		})
		return
	}
	ctx.JSON(http.StatusOK, server_structs.SimpleApiResp{
		Status: server_structs.RespOK,
		Msg:    "Ad OK",
	})
}

// Given an ad received from a remote service (e.g., a cache or origin),
// forward it to all to all known directors in the federation.
//
// If we determine this ad is from the currently-running, do not attempt to
// forward it to 'myself'.
func forwardServiceAd(engineCtx context.Context, serviceAd *server_structs.OriginAdvertiseV2, sType server_structs.ServerType) {
	directorAdMutex.RLock()
	defer directorAdMutex.RUnlock()
	directorAds.Range(func(item *ttlcache.Item[string, *directorInfo]) bool {
		dinfo := item.Value()
		if dinfo.ad == nil {
			return true
		}
		if self, err := server_utils.IsDirectorAdFromSelf(engineCtx, dinfo.ad); err == nil && !self {
			dinfo.forwardService(serviceAd, sType)
		}
		return true
	})
}

// Forward a director ad to the single director represented by the `dir` object.
//
// Note: the implementation is similar to `forwardService` but there are two
// functions to avoid refactoring the DirectorAd and OriginAdvertiseV2 to have
// a common interface.
func (dir *directorInfo) forwardDirector(ad *server_structs.DirectorAd) {
	forwardAd := &forwardAd{
		DirectorAd: ad,
		AdType:     server_structs.DirectorType.String(),
		Now:        time.Now(),
	}

	var buf *bytes.Buffer
	if adBytes, err := json.Marshal(forwardAd); err != nil {
		log.Errorln("Failed to marshal director ad to JSON when sending to", dir.ad.AdvertiseUrl, ":", err)
		return
	} else {
		buf = bytes.NewBuffer(adBytes)
	}
	info := &forwardAdInfo{
		key:      ad.Name,
		adType:   server_structs.DirectorType,
		contents: buf,
	}
	info.serverBase.CopyFrom(ad)

	dir.forwardAdChan <- info
}

// Forward a given service ad (cache, origin) to the single director represented
// by the `dir` object.
//
// Internally, writes the forwarding information to a channel and the separate
// goroutine will do the sending.  This allows the goroutine to drop duplicate
// updates if they are received before one update to the upstream director is
// completed.
func (dir *directorInfo) forwardService(ad *server_structs.OriginAdvertiseV2, sType server_structs.ServerType) {
	var buf *bytes.Buffer
	if adBytes, err := json.Marshal(ad); err != nil {
		log.Errorln("Failed to marshal director ad to JSON when sending to", dir.ad.AdvertiseUrl, ":", err)
		return
	} else {
		buf = bytes.NewBuffer(adBytes)
	}
	info := &forwardAdInfo{
		key:      ad.Name,
		adType:   sType,
		contents: buf,
	}
	info.serverBase.CopyFrom(ad)

	dir.forwardAdChan <- info
}

// Launch two goroutines to handle the forwarding of director ads
//
// The first goroutine will buffer pending ads; it'll save the single, most-recent
// ad per known director endpoint.  The second goroutine will read on ad off the
// queue at a time and send it to the remote director
func (dir *directorInfo) launchForwardAds(ctx context.Context, egrp *errgroup.Group) {
	advertiseUrl := dir.ad.AdvertiseUrl
	dir.internalAdChan = make(chan *forwardAdInfo) // Note no buffering: we only send an ad to the director forwarding goroutine when it is ready

	// This goroutine coalesces pending ads into only the latest update
	egrp.Go(func() error {
		pendingAds := make(map[string]*forwardAdInfo, 5)
		for {
			nextName := ""
			var nextAd *forwardAdInfo = nil
			// If there's nothing in the buffer, `nextChan` will be nil which
			// will prevent the write case in the `select` from firing.
			var nextChan chan *forwardAdInfo = nil
			for name, ad := range pendingAds {
				nextName = name
				nextAd = ad
				nextChan = dir.internalAdChan
				break
			}
			select {
			case <-ctx.Done():
				return nil
			case ad := <-dir.forwardAdChan:
				if existingAd := pendingAds[ad.key]; existingAd == nil {
					pendingAds[ad.key] = ad
				} else {
					if ad.serverBase.After(existingAd.serverBase) == server_structs.AdAfterTrue {
						pendingAds[ad.key] = ad
					}
				}
			case nextChan <- nextAd:
				delete(pendingAds, nextName)
			}
		}
	})

	egrp.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return nil
			case ad := <-dir.internalAdChan:
				dir.sendAd(ctx, advertiseUrl, ad)
			}
		}
	})
}

// Generate a token appropriate for sending ads to another director in the same federation
func (dir *directorInfo) getDirectorToken(ctx context.Context) (string, error) {
	if time.Now().Add(time.Minute).Before(dir.token.expiry) {
		return dir.token.token, nil
	}

	tokenCfg := token.NewWLCGToken()
	tokenCfg.Lifetime = time.Minute * 20
	fedInfo, err := config.GetFederation(ctx)
	if err != nil {
		return "", err
	}
	tokenCfg.Issuer = fedInfo.DiscoveryEndpoint
	aud, err := token.GetWLCGAudience(dir.ad.AdvertiseUrl)
	if err != nil {
		return "", err
	}
	tokenCfg.AddAudiences(aud)
	tokenCfg.Subject, err = getMyName(ctx)
	if err != nil {
		return "", err
	}
	tokenCfg.AddScopes(token_scopes.Pelican_DirectorAdvertise)

	if token, err := tokenCfg.CreateToken(); err == nil {
		dir.token.token = token
		dir.token.expiry = time.Now().Add(tokenCfg.Lifetime)
	} else if time.Now().After(dir.token.expiry) {
		return "", err
	}
	return dir.token.token, nil
}

// Send a single ad to a remote director
func (dir *directorInfo) sendAd(ctx context.Context, directorUrlStr string, ad *forwardAdInfo) {
	token, err := dir.getDirectorToken(ctx)
	if err != nil {
		log.Errorln("Failed to create a token for forwarding ad to director", directorUrlStr, ":", err)
		return
	}

	directorUrl, err := url.Parse(directorUrlStr)
	if err != nil {
		log.Errorln("Failed to parse URL for forwarding ad to director:", directorUrlStr)
		return
	}
	directorUrl.Path, err = url.JoinPath(directorUrl.Path, "api", "v1.0", "director", "registerDirector")
	if err != nil {
		log.Errorln("Failed to determine location of director advertisement endpoint")
		return
	}

	client := http.Client{Transport: config.GetTransport()}
	req, err := http.NewRequestWithContext(ctx, "POST", directorUrl.String(), ad.contents)
	if err != nil {
		log.Errorln("Failed to generate a new HTTP request:", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	userAgent := "pelican-director/" + version.GetVersion()
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		log.Errorln("Failed to send advertisement to", directorUrl.String(), ":", err)
		return
	}
	if resp.StatusCode != http.StatusOK {
		log.Errorln("Remote director at", directorUrl.String(), "rejected our forwarded ad:", err)
		body, _ := io.ReadAll(resp.Body)
		log.Debugln("Response body:", string(body))
		return
	}
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	if err != nil {
		log.Errorln("Remote director failed to send the response body", err)
		return
	}
}

// Return the name used by the service
//
// Utilizes server_utils.GetServiceName but caches the result in
// this module for faster lookups
func getMyName(ctx context.Context) (string, error) {
	directorNameOnce.Do(func() {
		directorName, directorNameError = server_utils.GetServiceName(ctx, server_structs.DirectorType)
	})
	if directorNameError != nil {
		return "", directorNameError
	}
	return directorName, nil
}

// Create an ad representing the current director service and forward it to all known
// directors (except myself).
func sendMyAd(ctx context.Context) {
	name, err := getMyName(ctx)
	if err != nil {
		log.Errorln("Local service does not know its own name (cannot forward ad to remote directors):", err)
		return
	}
	adUrl := param.Director_AdvertiseUrl.GetString()
	if adUrl == "" {
		adUrl = param.Server_ExternalWebUrl.GetString()
	}
	directorAd := &server_structs.DirectorAd{
		AdvertiseUrl: adUrl,
	}
	directorAd.Initialize(name)

	directorAdMutex.RLock()
	defer directorAdMutex.RUnlock()
	directorAds.Range(func(item *ttlcache.Item[string, *directorInfo]) bool {
		dinfo := item.Value()
		if dinfo.ad == nil {
			return true
		}
		if self, err := server_utils.IsDirectorAdFromSelf(ctx, dinfo.ad); err == nil && !self {
			dinfo.forwardDirector(directorAd)
		}
		return true
	})
}

// Update the internal directorAds cache with the provided ad
//
// MUST be called with the directorAdMutex write lock held
func updateInternalDirectorCache(ctx context.Context, egrp *errgroup.Group, directorAd *server_structs.DirectorAd) {
	if directorAd == nil {
		log.Debugln("Received nil director ad, skipping update")
		return
	}

	info := &directorInfo{}
	if directorAd.Name == "" {
		log.Debugln("Received director ad with empty name, skipping update")
		return
	}
	adTTL := time.Until(directorAd.Expiration)
	if directorAd.Expiration.IsZero() {
		adTTL = param.Director_AdvertisementTTL.GetDuration()
		if adTTL == 0 {
			log.Info(param.Director_AdvertisementTTL.GetName(), "is set to 0; increasing to 15 minutes")
			adTTL = 15 * time.Minute
		}
	} else if adTTL <= 0 {
		return
	}
	if item, found := directorAds.GetOrSet(directorAd.Name, info, ttlcache.WithTTL[string, *directorInfo](adTTL)); found {
		if item.Value() != nil && item.Value().ad != nil {
			if after := directorAd.After(item.Value().ad); after == server_structs.AdAfterTrue || after == server_structs.AdAfterUnknown {
				directorAds.Set(directorAd.Name, info, adTTL)
				if after == server_structs.AdAfterTrue {
					directorAds.Range(func(item *ttlcache.Item[string, *directorInfo]) bool {
						if item.Value() != nil && item.Value().ad != nil {
							if self, err := server_utils.IsDirectorAdFromSelf(ctx, item.Value().ad); err == nil && !self {
								item.Value().forwardDirector(directorAd)
							}
						}
						return true
					})
				}
			}
		}
	} else {
		info.ad = directorAd
		var fwdCtx context.Context
		fwdCtx, info.cancel = context.WithCancel(ctx)
		info.forwardAdChan = make(chan *forwardAdInfo, 5)
		go info.launchForwardAds(fwdCtx, egrp)
	}
}

// Go through the list of directors discovered via the periodic
// discovery routine in server_utils (done by every server) and add
// them to our known list of ads and channels
func updateDirectorAds(ctx context.Context) {
	egrp := ctx.Value(config.EgrpKey).(*errgroup.Group)
	directorAdMutex.Lock()
	defer directorAdMutex.Unlock()
	for _, directorAd := range server_utils.GetDirectorAds() {
		adCopy := directorAd
		updateInternalDirectorCache(ctx, egrp, &adCopy)
	}
}

// Periodically advertise our existence to all known directors
func LaunchPeriodicAdvertise(ctx context.Context) {
	updateDirectorAds(ctx)
	sendMyAd(ctx)
	egrp := ctx.Value(config.EgrpKey).(*errgroup.Group)
	adInterval := param.Server_AdvertisementInterval.GetDuration()
	expiryTime := param.Server_AdLifetime.GetDuration()
	if adInterval > expiryTime/3 {
		log.Warningln("The director advertise interval", adInterval.String(), "is set to above 1/3 of the ad lifetime.  Decreasing it to", expiryTime/3)
		adInterval = expiryTime / 3
	}

	ticker := time.NewTicker(adInterval)
	egrp.Go(func() error {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				updateDirectorAds(ctx)
				sendMyAd(ctx)
			}
		}
	})
}

// Reset the internal state of the director
//
// Primarily intended for unit tests to clear out state.
func ResetState() {
	directorAds = ttlcache.New(
		ttlcache.WithTTL[string, *directorInfo](15*time.Minute),
		ttlcache.WithDisableTouchOnHit[string, *directorInfo](),
	)
}
