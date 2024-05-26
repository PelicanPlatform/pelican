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
	"encoding/json"
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

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

type globusExportStatus string

// Internally for globusExports map
type globusExport struct {
	DisplayName      string             `json:"displayName"`
	FederationPrefix string             `json:"federationPrefix"`
	Status           globusExportStatus `json:"status"`
	Description      string             `json:"description"` // status description
	HttpsServer      string             `json:"httpsServer"` // server url to access files in the collection
	Token            *oauth2.Token      `json:"-"`
}

// For frontend to show an array of Globus exports
type globusExportUI struct {
	ID string `json:"id"`
	globusExport
}

const (
	globusInactive  = "Inactive"
	globusActivated = "Activated"
)

const globusTokenFileExt = ".tok" // File extension for caching Globus access token

var (
	globusExports      map[string]*globusExport // Key is the collection UUID
	globusExportsMutex = sync.RWMutex{}
)

func (g *globusExport) MarshalJSON() ([]byte, error) {
	type Alias globusExport
	expireStr := ""
	if g.Token == nil || g.Token.Expiry.IsZero() {
		expireStr = ""
	} else {
		expireStr = g.Token.Expiry.Format(time.RFC3339)
	}
	return json.Marshal(&struct {
		ExpireAt string `json:"expireAt"`
		*Alias
	}{
		ExpireAt: expireStr,
		Alias:    (*Alias)(g),
	})
}

func InitGlobusBackend(exps []server_utils.OriginExport) error {
	if server_utils.OriginStorageType(param.Origin_StorageType.GetString()) != server_utils.OriginStorageGlobus {
		return fmt.Errorf("failed to initialize Globus backend: Origin.StorageType is not Globus: %s",
			param.Origin_StorageType.GetString())
	}
	// Init map
	globusExports = make(map[string]*globusExport)

	// Check and setup token location
	tokFdr := param.Origin_GlobusTokenLocation.GetString()
	if err := os.MkdirAll(tokFdr, 0755); err != nil {
		return errors.Wrapf(err, "failed to create directory for Globus tokens: %s", tokFdr)
	}

	// Set up Globus map
	func() {
		globusExportsMutex.Lock()
		defer globusExportsMutex.Unlock()
		for _, esp := range exps {
			globusExp := globusExport{
				DisplayName:      esp.GlobusCollectionName,
				FederationPrefix: esp.FederationPrefix,
				Status:           globusInactive,
				Description:      "Server start",
			}
			// If no DisplayName set in exports, use ID instead
			if globusExp.DisplayName == "" {
				globusExp.DisplayName = esp.GlobusCollectionID
			}
			// If a token already exists at server start, remove the token
			tokLoc := filepath.Join(tokFdr, esp.GlobusCollectionID+globusTokenFileExt)
			if _, err := os.Stat(tokLoc); err == nil { // token file exists
				if err := os.Remove(tokLoc); err != nil {
					log.Errorf("Failed to remove expired Globus access token from %s", tokLoc)
				} else {
					log.Debugf("Removed expired Globus access token at %s", tokLoc)
				}
			}
			globusExports[esp.GlobusCollectionID] = &globusExp
		}
	}()

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
			return exp.Status == globusActivated
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
			if exp.Status == globusInactive {
				return nil
			}
			newTok, err := refreshGlobusToken(cid, exp.Token)
			if err != nil {
				log.Errorf("Failed to refresh Globus token for collection %s with name %s. Will retry once: %v", cid, exp.DisplayName, err)
				newTok, err = refreshGlobusToken(cid, exp.Token)
				if err != nil {
					log.Errorf("Failed to retry refreshing Globus token for collection %s with name %s: %v", cid, exp.DisplayName, err)
					exp.Status = globusInactive
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

// Parse the globusExports map into an array of globusExportUI for frontend RESTful API
func getGlobusExportsList() []globusExportUI {
	globusExportsMutex.RLock()
	defer globusExportsMutex.RUnlock()
	exportList := []globusExportUI{}
	for key, val := range globusExports {
		exportList = append(exportList, globusExportUI{
			ID:           key,
			globusExport: *val,
		})
	}

	// Sort the export by status then federation prefix
	sort.Slice(exportList, func(i, j int) bool {
		if exportList[i].Status == exportList[j].Status {
			return exportList[i].FederationPrefix < exportList[j].FederationPrefix
		} else {
			return exportList[i].Status < exportList[j].Status
		}
	})

	return exportList
}

// Handle listing all Globus exports
func listGlobusExports(ctx *gin.Context) {
	exportList := getGlobusExportsList()
	ctx.JSON(http.StatusOK, exportList)
}
