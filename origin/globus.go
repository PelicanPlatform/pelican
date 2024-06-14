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

package origin

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

type globusExportStatus string

// For internal globusExports map
type globusExport struct {
	DisplayName      string             `json:"displayName"`
	FederationPrefix string             `json:"federationPrefix"`
	Status           globusExportStatus `json:"status"`
	Description      string             `json:"description,omitempty"` // status description
	HttpsServer      string             `json:"httpsServer"`           // server url to access files in the collection
	Token            *oauth2.Token      `json:"-"`
}

// For UI
type globusExportUI struct {
	globusExport
	UUID string `json:"uuid"`
}

const (
	GlobusInactive  = "Inactive"
	GlobusActivated = "Activated"
)

const GlobusTokenFileExt = ".tok" // File extension for caching Globus access token

var (
	// An in-memory map-struct to keep Globus collections information with key being the collection UUID.
	globusExports      map[string]*globusExport
	globusExportsMutex = sync.RWMutex{}
)

// InitGlobusBackend does the following things to initialize Globus-related logic
//  1. It initializes the global map strcuture globusExports to store collection information in-memory
//  2. It checks and setup location for Globus access tokens after user activates the collection
//  3. It loads the Globus OAuth client for OAuth-based authorization to access collection data
//  4. It populates the global map by the exported Origin prefixes/collections. It reads the persisted credentials
//     from the origin's SQLite DB and populate the global map, refresh the access token by the persisted
//     refresh token
func InitGlobusBackend(exps []server_utils.OriginExport) error {
	uid, err := config.GetDaemonUID()
	if err != nil {
		return errors.Wrap(err, "failed to initialize Globus backend: failed to get uid")
	}

	gid, err := config.GetDaemonGID()
	if err != nil {
		return errors.Wrap(err, "failed to initialize Globus backend: failed to get gid")
	}

	if server_utils.OriginStorageType(param.Origin_StorageType.GetString()) != server_utils.OriginStorageGlobus {
		return errors.Errorf("failed to initialize Globus backend: Origin.StorageType is not Globus: %s",
			param.Origin_StorageType.GetString())
	}
	// Init map
	globusExports = make(map[string]*globusExport)

	// Check and setup token location
	globusFdr := param.Origin_GlobusConfigLocation.GetString()
	tokFdr := filepath.Join(globusFdr, "tokens")
	if err := os.MkdirAll(tokFdr, 0755); err != nil {
		return errors.Wrapf(err, "failed to create directory for Globus tokens: %s", tokFdr)
	}
	// We need to change the directory and file permission to XRootD user/group so that it can access the token
	if err = os.Chown(globusFdr, uid, gid); err != nil {
		return errors.Wrapf(err, "unable to change the ownership of %s to xrootd daemon uid %d and gid %d for Globus config", globusFdr, uid, gid)
	}
	if err = os.Chown(tokFdr, uid, gid); err != nil {
		return errors.Wrapf(err, "unable to change the ownership of %s to xrootd daemon uid %d and gid %d for Globus tokens", tokFdr, uid, gid)
	}

	globusAuthCfg, err := GetGlobusOAuthCfg()
	if err != nil {
		return errors.Wrap(err, "failed to get Globus OAuth2 config")
	}

	// Populate globusExports map
	globusExportsMutex.Lock()
	defer globusExportsMutex.Unlock()
	for _, esp := range exps {
		globusEsp := globusExport{
			DisplayName:      esp.GlobusCollectionName,
			FederationPrefix: esp.FederationPrefix,
			Status:           GlobusInactive,
			Description:      "Server start",
		}
		// We check the origin db and see if we already have the refresh token in-place
		// If so, use the token to initialize the collection
		ok, err := collectionExistsByUUID(esp.GlobusCollectionID)
		if err != nil {
			return errors.Wrapf(err, "failed to check credential status for Globus collection %s with name %s", esp.GlobusCollectionID, esp.GlobusCollectionName)
		}
		if !ok {
			log.Infof("Globus collection %s with name %s is not activated. You need to activate it in the admin website before using this collection", esp.GlobusCollectionID, esp.GlobusCollectionName)
			globusExports[esp.GlobusCollectionID] = &globusEsp
			continue
		}
		// We found the collection in DB, try to get access token via the refresh token
		col, err := getCollectionByUUID(esp.GlobusCollectionID)
		if err != nil {
			return errors.Wrapf(err, "failed to get credentials for Globus collection %s with name %s", esp.GlobusCollectionID, esp.GlobusCollectionName)
		}

		refToken := &oauth2.Token{
			RefreshToken: col.RefreshToken,
		}
		tokenSource := globusAuthCfg.TokenSource(context.Background(), refToken)
		collectionToken, err := tokenSource.Token()
		// If we can't get the access token, we want to evict the entry from db and
		// ask the user to redo the authentication
		if err != nil {
			if err := deleteCollectionByUUID(col.UUID); err != nil {
				return errors.Wrapf(err, "failed to delete expired credential record for Globus collection %s with name %s", esp.GlobusCollectionID, esp.GlobusCollectionName)
			}
			log.Infof("Access credentials for Globus collection %s with name %s is expired and removed.", esp.GlobusCollectionID, esp.GlobusCollectionName)
		}

		// Save the new access token
		if err := persistAccessToken(col.UUID, collectionToken); err != nil {
			return err
		}

		// If no DisplayName set in exports, use the name from DB instead
		// which should be the display_name of the collection from Globus
		if globusEsp.DisplayName == "" {
			log.Infof("Globus collection doesn't have GlobusCollectionName set, default to the Globus value: %s", col.Name)
			globusEsp.DisplayName = col.Name
		}

		globusEsp.Status = GlobusActivated
		globusEsp.Token = collectionToken
		globusEsp.HttpsServer = col.ServerURL
		globusEsp.Description = "Activated with cached credentials"
		globusExports[esp.GlobusCollectionID] = &globusEsp
	}
	return nil
}

// Return whether a Globus collection export is activated based on its federation prefix.
//
// This function can be accessed by multiple goroutines simultaneously.
func isExportActivated(fedPrefix string) (ok bool) {
	globusExportsMutex.RLock()
	defer globusExportsMutex.RUnlock()
	for _, exp := range globusExports {
		if exp.FederationPrefix == fedPrefix {
			return exp.Status == GlobusActivated
		}
	}
	return false
}

// Iterate over all Globus exports and refresh the token. Skip any inactive exports.
// Retry once if first attempt failed. If retry failed, mark the activated export to inactive
// and provide error detail in the export description.
//
// Return the first error if any.
func doGlobusTokenRefresh() error {
	var firstErr error
	for cid, exp := range globusExports {
		err := func(cidInt string, expInt *globusExport) error {
			globusExportsMutex.Lock()
			defer globusExportsMutex.Unlock()
			// We can't refresh exports that are never activated
			if exp.Status == GlobusInactive {
				return nil
			}
			newTok, err := refreshGlobusToken(cid, exp.Token)
			if err != nil {
				log.Errorf("Failed to refresh Globus token for collection %s with name %s. Will retry once: %v", cid, exp.DisplayName, err)
				newTok, err = refreshGlobusToken(cid, exp.Token)
				if err != nil {
					log.Errorf("Failed to retry refreshing Globus token for collection %s with name %s: %v", cid, exp.DisplayName, err)
					exp.Status = GlobusInactive
					exp.Description = fmt.Sprintf("Failed to refresh token: %v", err)
					return err
				}
			}
			if newTok == nil {
				log.Debugf("Globus token for collection %s with name %s is still valid. Refresh skipped", cid, exp.DisplayName)
			} else {
				// Update globusExport with the new token
				expInt.Token = newTok
				log.Debugf("Globus token for collection %s with name %s is refreshed", cid, exp.DisplayName)
			}
			return nil
		}(cid, exp)
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return errors.Wrap(firstErr, "failed to refresh Globus tokens")
}

// Launch an errgroup goroutine to periodically (5min) refresh access tokens for activated Globus exports
func LaunchGlobusTokenRefresh(ctx context.Context, egrp *errgroup.Group) {
	log.Debug("Launching periodic update of Globus access token.")
	egrp.Go(func() error {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				log.Info("Periodic update of Globus access token is stopped.")
				return nil
			case <-ticker.C:
				if err := doGlobusTokenRefresh(); err != nil {
					log.Errorf("Failed to update Globus tokens: %v", err)
				}
			}
		}
	})
}

// Get all values of Globus exports map. Returned values are read-only
func GetGlobusExportsValues(activeOnly bool) []globusExport {
	globusExportsMutex.RLock()
	defer globusExportsMutex.RUnlock()
	exps := []globusExport{}
	for _, val := range globusExports {
		if activeOnly {
			if val.Status == GlobusActivated {
				exps = append(exps, *val)
			} else {
				continue
			}
		} else {
			exps = append(exps, *val)
		}
	}

	sort.Slice(exps, func(i, j int) bool {
		if exps[i].Status == exps[j].Status {
			return exps[i].FederationPrefix < exps[j].FederationPrefix
		} else {
			return exps[i].Status < exps[j].Status
		}
	})

	return exps
}

// Parse the OriginExport to add Globus status for each export for frontend RESTful API
func originExportToGlobusExport(exps []server_utils.OriginExport) ([]globusExportUI, error) {
	globusExportsMutex.RLock()
	defer globusExportsMutex.RUnlock()
	exportList := []globusExportUI{}
	for _, exp := range exps {
		if gexp, ok := globusExports[exp.GlobusCollectionID]; !ok {
			return nil, errors.Errorf("Globus collection %s is not found in Pelican", exp.GlobusCollectionID)
		} else {
			exportList = append(exportList, globusExportUI{
				UUID:         exp.GlobusCollectionID,
				globusExport: *gexp,
			})
		}
	}

	// Sort the export by status then federation prefix
	sort.Slice(exportList, func(i, j int) bool {
		if exportList[i].Status == exportList[j].Status {
			return exportList[i].FederationPrefix < exportList[j].FederationPrefix
		} else {
			return exportList[i].Status < exportList[j].Status
		}
	})

	return exportList, nil
}

// Handle listing all Globus exports
func listGlobusExports(ctx *gin.Context) {
	exps, err := server_utils.GetOriginExports()
	if err != nil {
		log.Errorf("Failed to get origin exports: %v", err)
		ctx.JSON(http.StatusInternalServerError,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to get origin exports: %v", err),
			})
		return
	}
	exportList, err := originExportToGlobusExport(exps)
	if err != nil {
		log.Errorf("Failed to get Globus exports: %v", err)
		ctx.JSON(http.StatusInternalServerError,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to get Globus exports: %v", err),
			})
		return
	}

	ctx.JSON(http.StatusOK, exportList)
}
