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

// Host-certificate manager (WS3, "reduce origin requirements"). When the
// federation runs a certificate authority (the registry, advertised via
// federation metadata as ca_endpoint), an origin or cache that would otherwise
// self-sign obtains a real, federation-trusted host certificate automatically —
// no operator configuration required.
//
// The design is deliberately non-blocking and failure-tolerant: the service
// always starts on the self-signed temporary certificate produced by
// config.GenerateCert(), and this manager swaps in a CA-issued certificate
// asynchronously once the service is registered and approved. A registry that
// is down, slow, or hasn't approved the service yet therefore never impacts the
// origin's startup or availability — it just keeps running on the temporary
// certificate and retries later. The certificate is served through the web
// engine's existing on-disk TLS watcher, so installing new files is all that is
// required for the running server to pick them up.
package launcher_utils

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/registry/registry_client"
	"github.com/pelicanplatform/pelican/server_structs"
)

const (
	// hostCertCheckInterval is how often the manager re-evaluates whether a
	// certificate needs to be obtained or renewed.
	hostCertCheckInterval = 10 * time.Minute

	// hostCertRenewBefore triggers renewal once the current CA-issued
	// certificate is within this window of expiring.
	hostCertRenewBefore = 48 * time.Hour

	// selfSignedIssuerOrg marks certificates produced by config.GenerateCACert
	// (the temporary, self-signed path). Such certs are replaceable.
	selfSignedIssuerOrg = "Pelican CA"

	// federationIssuerOrg marks certificates issued by the federation CA (see
	// registry/ca.go). Such certs are the real thing; only renew them.
	federationIssuerOrg = "Pelican Federation"
)

// LaunchHostCertificateManager starts the background manager for origins and
// caches. It never blocks and never fails startup.
func LaunchHostCertificateManager(ctx context.Context, egrp *errgroup.Group, modules server_structs.ServerType) {
	if !modules.IsEnabled(server_structs.OriginType) && !modules.IsEnabled(server_structs.CacheType) {
		return
	}

	egrp.Go(func() error {
		// Attempt once shortly after startup, then on a steady cadence.
		ticker := time.NewTicker(hostCertCheckInterval)
		defer ticker.Stop()
		for {
			if err := EnsureHostCertificate(ctx, modules); err != nil {
				log.Debugf("Host certificate manager: %v (will retry)", err)
			}
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
			}
		}
	})
}

// EnsureHostCertificate performs one best-effort acquire/renew cycle. Every
// early return is a benign "nothing to do / can't do it yet" condition; real
// failures are wrapped for the caller to log at debug level. Exported so
// integration tests can drive a single cycle without waiting on the manager's
// timer.
func EnsureHostCertificate(ctx context.Context, modules server_structs.ServerType) error {
	fedInfo, err := config.GetFederation(ctx)
	if err != nil {
		return errors.Wrap(err, "federation not yet discovered")
	}
	// Auto-detect: only act when the federation advertises a CA.
	if fedInfo.CAEndpoint == "" {
		return nil
	}

	needed, reason := hostCertNeedsIssue()
	if !needed {
		return nil
	}
	log.Infof("Host certificate manager: requesting a federation certificate (%s)", reason)

	prefix, err := serverRegistrationPrefix(modules)
	if err != nil {
		return err
	}
	registrationKey, err := config.GetIssuerPrivateJWK()
	if err != nil {
		return errors.Wrap(err, "failed to load registration key")
	}
	caBase, err := url.JoinPath(fedInfo.CAEndpoint, "api", "v1.0", "registry")
	if err != nil {
		return errors.Wrap(err, "failed to construct CA endpoint URL")
	}

	chainPEM, hostKeyPEM, err := registry_client.RequestHostCertificate(ctx, caBase, prefix, registrationKey)
	if err != nil {
		// The common cases here (not yet approved, registry unreachable) are
		// expected and transient — keep the temporary cert and retry.
		return errors.Wrap(err, "could not obtain a federation certificate")
	}
	rootPEM, err := registry_client.FetchCABundle(ctx, caBase)
	if err != nil {
		return errors.Wrap(err, "could not fetch the federation CA bundle")
	}

	if err := installHostCertificate(chainPEM, hostKeyPEM, rootPEM); err != nil {
		return errors.Wrap(err, "failed to install the federation certificate")
	}
	log.Info("Host certificate manager: installed a federation-issued host certificate; the TLS watcher will reload it")
	return nil
}

// hostCertNeedsIssue reports whether a (new) certificate should be obtained and
// a short human-readable reason. It respects operator-provided certificates: a
// certificate issued by something other than Pelican's self-signed or
// federation CA is left untouched.
func hostCertNeedsIssue() (bool, string) {
	cert, err := config.LoadCertificate(param.Server_TLSCertificateChain.GetString())
	if err != nil {
		return true, "no readable host certificate present"
	}
	issuerOrg := strings.Join(cert.Issuer.Organization, ",")
	switch {
	case strings.Contains(issuerOrg, federationIssuerOrg):
		// Already federation-issued; only renew as it nears expiry.
		if time.Until(cert.NotAfter) < hostCertRenewBefore {
			return true, "federation certificate nearing expiry"
		}
		return false, ""
	case strings.Contains(issuerOrg, selfSignedIssuerOrg):
		return true, "replacing self-signed temporary certificate"
	default:
		// Operator-provided certificate — do not touch it.
		return false, ""
	}
}

// serverRegistrationPrefix returns the registry prefix under which this service
// registered (which the registry maps to the service slug).
func serverRegistrationPrefix(modules server_structs.ServerType) (string, error) {
	if modules.IsEnabled(server_structs.OriginType) {
		extUrl, err := url.Parse(param.Server_ExternalWebUrl.GetString())
		if err != nil {
			return "", errors.Wrap(err, "failed to parse the external web URL")
		}
		return server_structs.GetOriginNs(extUrl.Host), nil
	}
	if modules.IsEnabled(server_structs.CacheType) {
		return server_structs.GetCacheNs(param.Xrootd_Sitename.GetString()), nil
	}
	return "", errors.New("no origin or cache module enabled")
}

// installHostCertificate writes the new material to the configured TLS paths.
// Files are written atomically (temp + rename) so the TLS watcher never reads a
// half-written pair; the key is written before the chain so that once the chain
// appears its matching key is already present.
func installHostCertificate(chainPEM, hostKeyPEM, rootPEM string) error {
	keyPath := param.Server_TLSKey.GetString()
	chainPath := param.Server_TLSCertificateChain.GetString()
	rootPath := param.Server_TLSCACertificateFile.GetString()

	if err := writeFileAtomic(rootPath, []byte(rootPEM), 0644); err != nil {
		return errors.Wrap(err, "failed to write the CA bundle")
	}
	if err := writeFileAtomic(keyPath, []byte(hostKeyPEM), 0400); err != nil {
		return errors.Wrap(err, "failed to write the host key")
	}
	if err := writeFileAtomic(chainPath, []byte(chainPEM), 0644); err != nil {
		return errors.Wrap(err, "failed to write the host certificate chain")
	}
	return nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".hostcert-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return nil
}
