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

	// Obtain server's active private key
	key, err := config.GetIssuerPrivateJWK()
	if err != nil {
		err = errors.Wrap(err, "Failed to obtain server's active private key")
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

// Check the issuer key directory containing .pem files every 5 minutes, load new private key(s)
// if new file(s) are detected, then register the new public key
func LaunchIssuerKeysDirRefresh(ctx context.Context, egrp *errgroup.Group) {
	egrp.Go(func() error {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Debugln("Stopping periodic check for private keys directory.")
				return nil
			case <-ticker.C:
				// Refresh the disk to pick up any new private key
				config.UpdatePreviousIssuerPrivateJWK()
				key, err := config.LoadIssuerPrivateKey(param.IssuerKeysDirectory.GetString())
				if err != nil {
					return err
				}
				log.Debugln("Private keys directory refreshed successfully. The active (latest) private key is", key.KeyID())
				log.Debugln("Previous private key is", config.GetPreviousIssuerPrivateJWK().KeyID())

				// Update public key in registry db with the new active private key
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

			}
		}
	})
}