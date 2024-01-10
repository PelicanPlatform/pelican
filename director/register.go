/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

type (
	// Wire format for advertising a server (cache, origin) to the director.
	ServerAdvertise struct {
		Name         string        `json:"name"`
		URL          string        `json:"url"`               // This is the url for origin's XRootD service and file transfer
		WebURL       string        `json:"web_url,omitempty"` // This is the url for origin's web engine and APIs
		Namespaces   []NamespaceAd `json:"namespaces"`
		WriteEnabled bool          `json:"writeenabled"`
	}

	// Wire format describing a namespace that a (cache, origin) server is willing
	// to service.
	NamespaceAd struct {
		RequireToken  bool         `json:"requireToken"`
		Path          string       `json:"path"`
		Issuer        url.URL      `json:"url"`
		MaxScopeDepth uint         `json:"maxScopeDepth"`
		Strategy      StrategyType `json:"strategy"`
		BasePath      string       `json:"basePath"`
		VaultServer   string       `json:"vaultServer"`
		DirlistHost   string       `json:"dirlisthost"`
	}
)

func registerServeAd(engineCtx context.Context, ctx *gin.Context, sType ServerType) {
	tokens, present := ctx.Request.Header["Authorization"]
	if !present || len(tokens) == 0 {
		ctx.JSON(http.StatusForbidden, gin.H{"error": "Bearer token not present in the 'Authorization' header"})
		return
	}

	err := versionCompatCheck(ctx)
	if err != nil {
		log.Debugf("A version incompatibility was encountered while registering %s and no response was served: %v", sType, err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Incompatible versions detected: " + fmt.Sprintf("%v", err)})
		return
	}

	ad := ServerAdvertise{}
	if ctx.ShouldBind(&ad) != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid " + sType + " registration"})
		return
	}

	if sType == OriginType {
		for _, namespace := range ad.Namespaces {
			// We're assuming there's only one token in the slice
			token := strings.TrimPrefix(tokens[0], "Bearer ")
			ok, err := verifyAdvertiseToken(engineCtx, token, namespace.Path)
			if err != nil {
				log.Warningln("Failed to verify token:", err)
				ctx.JSON(http.StatusForbidden, gin.H{"error": "Authorization token verification failed"})
				return
			}
			if !ok {
				log.Warningf("%s %v advertised to namespace %v without valid registration\n",
					sType, ad.Name, namespace.Path)
				ctx.JSON(http.StatusForbidden, gin.H{"error": sType + " not authorized to advertise to this namespace"})
				return
			}
		}
	} else {
		token := strings.TrimPrefix(tokens[0], "Bearer ")
		prefix := path.Join("caches", ad.Name)
		ok, err := verifyAdvertiseToken(engineCtx, token, prefix)
		if err != nil {
			if err == adminApprovalErr {
				log.Warningln("Failed to verify token. Cache was not approved:", err)
				ctx.JSON(http.StatusForbidden, gin.H{"error": "Cache is not admin approved"})
			} else {
				log.Warningln("Failed to verify token:", err)
				ctx.JSON(http.StatusForbidden, gin.H{"error": "Authorization token verification failed"})
			}
			return
		}
		if !ok {
			log.Warningf("%s %v advertised to namespace %v without valid registration\n",
				sType, ad.Name, prefix)
			ctx.JSON(http.StatusForbidden, gin.H{"error": sType + " not authorized to advertise to this namespace"})
			return
		}
	}

	ad_url, err := url.Parse(ad.URL)
	if err != nil {
		log.Warningf("Failed to parse %s URL %v: %v\n", sType, ad.URL, err)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid " + sType + " URL"})
		return
	}

	adWebUrl, err := url.Parse(ad.WebURL)
	if err != nil && ad.WebURL != "" { // We allow empty WebURL string for backward compatibility
		log.Warningf("Failed to parse origin Web URL %v: %v\n", ad.WebURL, err)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid origin Web URL"})
		return
	}

	sAd := serverDesc{
		Name:         ad.Name,
		AuthURL:      *ad_url,
		URL:          *ad_url,
		WebURL:       *adWebUrl,
		Type:         sType,
		WriteEnabled: ad.WriteEnabled,
	}

	hasOriginAdInCache := serverAds.Has(sAd)
	recordAd(sAd, &ad.Namespaces)

	// Start director periodic test of origin's health status if origin AD
	// has WebURL field AND it's not already been registered
	healthTestCancelFuncsMutex.Lock()
	defer healthTestCancelFuncsMutex.Unlock()
	if ad.WebURL != "" && !hasOriginAdInCache {
		ctx, cancel := context.WithCancel(context.Background())
		healthTestCancelFuncs[sAd] = cancel
		launchPeriodicDirectorTest(ctx, sAd)
	}

	ctx.JSON(http.StatusOK, gin.H{"msg": "Successful registration"})
}

func RegisterOrigin(ctx context.Context, gctx *gin.Context) {
	registerServeAd(ctx, gctx, OriginType)
}

func RegisterCache(ctx context.Context, gctx *gin.Context) {
	registerServeAd(ctx, gctx, CacheType)
}
