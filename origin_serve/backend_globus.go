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

package origin_serve

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/webdav"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/server_utils"
)

// ---------------------------------------------------------------------------
// globusBackend — OriginBackend for Globus v2 (via HTTPS + Globus tokens)
// ---------------------------------------------------------------------------

// GlobusBackendActivator provides methods for activating and refreshing
// a Globus v2 backend. It is the exported interface that external packages
// (e.g. launchers) use to manage Globus backends.
type GlobusBackendActivator interface {
	// Activate marks the collection as activated with the given tokens.
	Activate(collectionToken, transferToken *oauth2.Token, httpsServer string)
	// RefreshTokens refreshes both the collection and transfer tokens.
	RefreshTokens() error
	// IsActivated returns whether the Globus collection has been activated.
	IsActivated() bool
}

// globusBackend wraps an httpsBackend with Globus-specific token management.
// The HTTPS filesystem reads files from the Globus collection's HTTPS endpoint,
// using an OAuth2 access token obtained through the Globus auth flow.
//
// Unlike the XRootD Globus backend, tokens are managed in memory only — no
// disk persistence is needed because the origin_serve infrastructure does
// not need to share tokens with an XRootD process.
type globusBackend struct {
	inner *httpsBackend

	// Globus-specific token management
	collectionID    string
	mu              sync.RWMutex
	collectionToken *oauth2.Token
	transferToken   *oauth2.Token
	oauth2Cfg       *oauth2.Config
	httpsServer     string // Collection HTTPS endpoint
	activated       bool
}

// GlobusBackendConfig holds the parameters needed to construct a Globus backend.
type GlobusBackendConfig struct {
	// CollectionID is the Globus collection UUID
	CollectionID string
	// HTTPSServer is the HTTPS URL for the collection (e.g. https://g-12345.data.globus.org)
	HTTPSServer string
	// StoragePrefix is the path prefix within the collection
	StoragePrefix string
	// OAuth2Config for refreshing tokens
	OAuth2Config *oauth2.Config
	// CollectionToken is the initial collection access token
	CollectionToken *oauth2.Token
	// TransferToken is the initial transfer access token
	TransferToken *oauth2.Token
}

// NewGlobusBackend creates a new native Globus backend.
func NewGlobusBackend(cfg GlobusBackendConfig) *globusBackend {
	inner := newHTTPSBackend(HTTPSBackendOptions{
		ServiceURL:      cfg.HTTPSServer,
		StoragePrefix:   cfg.StoragePrefix,
		TokenMode:       HTTPSTokenOAuth2,
		OAuth2Config:    cfg.OAuth2Config,
		OAuth2Token:     cfg.CollectionToken,
		EnableAutoMkdir: true,
	})

	return &globusBackend{
		inner:           inner,
		collectionID:    cfg.CollectionID,
		collectionToken: cfg.CollectionToken,
		transferToken:   cfg.TransferToken,
		oauth2Cfg:       cfg.OAuth2Config,
		httpsServer:     cfg.HTTPSServer,
		activated:       cfg.CollectionToken != nil,
	}
}

func (b *globusBackend) CheckAvailability() error {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if !b.activated {
		return &globusUnavailableError{
			collectionID: b.collectionID,
			msg:          "Globus collection not activated",
		}
	}
	return nil
}

func (b *globusBackend) FileSystem() webdav.FileSystem { return b.inner.FileSystem() }

func (b *globusBackend) Checksummer() server_utils.OriginChecksummer {
	// TODO: Globus collections may provide checksums via the Transfer API
	// (GET /endpoint/<id>/ls with checksum fields).  Investigate whether
	// we can surface those through the OriginChecksummer interface.
	return nil
}

// IsActivated returns whether the Globus collection has been activated.
func (b *globusBackend) IsActivated() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.activated
}

// Activate marks the collection as activated with the given tokens.
func (b *globusBackend) Activate(collectionToken, transferToken *oauth2.Token, httpsServer string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.collectionToken = collectionToken
	b.transferToken = transferToken
	b.httpsServer = httpsServer
	b.activated = true

	// Update the inner HTTPS backend's OAuth2 token
	b.inner.SetOAuth2Token(collectionToken)
}

// RefreshTokens refreshes both the collection and transfer tokens.
func (b *globusBackend) RefreshTokens() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.activated || b.oauth2Cfg == nil {
		return nil
	}

	// Refresh collection token
	if b.collectionToken != nil && b.collectionToken.Expiry.Before(time.Now().Add(10*time.Minute)) {
		ts := b.oauth2Cfg.TokenSource(nil, b.collectionToken)
		newTok, err := ts.Token()
		if err != nil {
			log.Warningf("Failed to refresh Globus collection token for %s: %v", b.collectionID, err)
			b.activated = false
			return fmt.Errorf("failed to refresh collection token: %w", err)
		}
		b.collectionToken = newTok
		b.inner.SetOAuth2Token(newTok)
		log.Debugf("Refreshed Globus collection token for %s", b.collectionID)
	}

	// Refresh transfer token
	if b.transferToken != nil && b.transferToken.Expiry.Before(time.Now().Add(10*time.Minute)) {
		ts := b.oauth2Cfg.TokenSource(nil, b.transferToken)
		newTok, err := ts.Token()
		if err != nil {
			log.Warningf("Failed to refresh Globus transfer token for %s: %v", b.collectionID, err)
			return fmt.Errorf("failed to refresh transfer token: %w", err)
		}
		b.transferToken = newTok
		log.Debugf("Refreshed Globus transfer token for %s", b.collectionID)
	}

	return nil
}

// ---------------------------------------------------------------------------
// globusUnavailableError — HTTP 503 when collection is not activated
// ---------------------------------------------------------------------------

type globusUnavailableError struct {
	collectionID string
	msg          string
}

func (e *globusUnavailableError) Error() string {
	return fmt.Sprintf("Globus collection %s: %s", e.collectionID, e.msg)
}

func (e *globusUnavailableError) HTTPStatusCode() int {
	return http.StatusServiceUnavailable
}

// GetGlobusBackends returns the map of Globus v2 backends keyed by collection ID.
// This is used by the launcher to activate backends after Globus OAuth is initialized.
func GetGlobusBackends() map[string]GlobusBackendActivator {
	result := make(map[string]GlobusBackendActivator, len(globusBackends))
	for k, v := range globusBackends {
		result[k] = v
	}
	return result
}

// LaunchGlobusv2TokenRefresh starts a periodic goroutine (every 5 min) that
// refreshes the OAuth2 tokens for all activated Globus v2 backends.
func LaunchGlobusv2TokenRefresh(ctx context.Context, egrp *errgroup.Group) {
	if len(globusBackends) == 0 {
		return
	}
	log.Info("Launching periodic Globus v2 token refresh")
	egrp.Go(func() error {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				log.Info("Globus v2 token refresh stopped")
				return nil
			case <-ticker.C:
				for cid, gb := range globusBackends {
					if err := gb.RefreshTokens(); err != nil {
						log.Errorf("Failed to refresh Globus v2 tokens for collection %s: %v", cid, err)
					}
				}
			}
		}
	})
}
