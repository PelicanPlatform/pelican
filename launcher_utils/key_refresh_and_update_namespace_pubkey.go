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

package launcher_utils

import (
	"context"
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/registry"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

func updateNamespacesPubKeyPrep(ctx context.Context, prefixes []string) (jwk.Key, string, error) {
	// Validate the namespace format
	for _, prefix := range prefixes {
		if prefix == "" {
			err := errors.New("Invalid empty prefix for public key update")
			return nil, "", err
		}
		if prefix[0] != '/' {
			err := errors.New("Prefix specified for public key update must start with a '/'")
			return nil, "", err
		}
	}

	// Generate the endpoint url that can update the public key of prefixes
	fedInfo, err := config.GetFederation(ctx)
	if err != nil {
		return nil, "", err
	}
	registryEndpoint := fedInfo.RegistryEndpoint
	if registryEndpoint == "" {
		err = errors.New("No registry endpoint specified; try passing the `-f` flag specifying the federation name")
		return nil, "", err
	}

	prefixPubKeyUpdateUrl, err := url.JoinPath(registryEndpoint, "api", "v1.0", "registry", "updateNamespacesPubKey")
	if err != nil {
		err = errors.Wrap(err, "Failed to construct public key update endpoint URL: %v")
		return nil, "", err
	}

	// Obtain server's issuer private key
	key, err := config.GetIssuerPrivateJWK()
	if err != nil {
		err = errors.Wrap(err, "Failed to obtain server's issuer private key")
		return nil, "", err
	}

	return key, prefixPubKeyUpdateUrl, nil
}

func updateNamespacesPubKey(ctx context.Context, prefixes []string) error {
	siteName := param.Xrootd_Sitename.GetString()

	key, url, err := updateNamespacesPubKeyPrep(ctx, prefixes)
	if err != nil {
		return err
	}
	if err = registry.NamespacesPubKeyUpdate(key, prefixes, siteName, url); err != nil {
		return err
	}
	return nil
}

func triggerNamespacesPubKeyUpdate(ctx context.Context) error {
	extUrlStr := param.Server_ExternalWebUrl.GetString()
	extUrl, _ := url.Parse(extUrlStr)
	namespace := server_structs.GetOriginNs(extUrl.Host)
	if err := updateNamespacesPubKey(ctx, []string{namespace}); err != nil {
		log.Errorf("Error updating the public key of the registered origin namespace %s: %v", namespace, err)
	}

	originExports, err := server_utils.GetOriginExports()
	if err != nil {
		return err
	}
	originExportsNs := make([]string, len(originExports))
	for i, export := range originExports {
		originExportsNs[i] = export.FederationPrefix
	}
	if err := updateNamespacesPubKey(ctx, originExportsNs); err != nil {
		log.Errorf("Error updating the public key of origin-exported namespace(s): %v", err)
	}
	return nil
}

// KeyChangeCallback is a callback function type that is called when issuer keys change.
// The callback receives the context and should return an error if the operation fails.
type KeyChangeCallback func(ctx context.Context) error

// Check the directory containing .pem files regularly, load new private key(s)
// For origin server, if new file(s) are detected, then register the new public key
// Optional callbacks can be provided to be invoked when keys change.
func LaunchIssuerKeysDirRefresh(ctx context.Context, egrp *errgroup.Group, modules server_structs.ServerType, callbacks ...KeyChangeCallback) {
	server_utils.LaunchWatcherMaintenance(
		ctx,
		[]string{param.IssuerKeysDirectory.GetString()},
		"private key refresh and registration",
		time.Minute,
		func( /*notifyEvent*/ bool) error {
			// Refresh the disk to pick up any new private key
			keysChanged, err := config.RefreshKeys()
			if err != nil {
				return nil
			}

			if keysChanged {
				// Update public key registered with namespace in registry db when the private key(s) changed in an origin
				if modules.IsEnabled(server_structs.OriginType) {
					if err = triggerNamespacesPubKeyUpdate(ctx); err != nil {
						return err
					}
				}

				// Call any registered callbacks when keys change
				for _, callback := range callbacks {
					if err := callback(ctx); err != nil {
						log.Errorf("Key change callback failed: %v", err)
					}
				}
			}
			return nil
		},
	)
}
