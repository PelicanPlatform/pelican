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

// Startup validation for Origin.EnableStandaloneMode: the settings a standalone
// origin cannot honor, and the federation prefixes it has been told to export.

package config

import (
	"path"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

// validateStandaloneOrigin rejects configurations where Origin.EnableStandaloneMode
// is set but the rest of the configuration still assumes a federation.
//
// Standalone mode is deliberately narrow: it disconnects the origin from the
// director and registry, which are exactly the components that supply the
// XRootD-fronted backends with their configuration and that make the
// "direct clients are forbidden" policy meaningful.  Rather than silently
// half-applying the mode, fail at startup with an actionable message.
func validateStandaloneOrigin(currentServers server_structs.ServerType) error {
	standaloneName := param.Origin_EnableStandaloneMode.GetName()

	// Only the native "v2" backends are served in-process; the XRootD-fronted
	// ones build their config (authfile, issuer list, scitokens config) from
	// federation metadata and expect a director to test them.
	storageType := server_structs.OriginStorageType(param.Origin_StorageType.GetString())
	if storageType.UsesXRootD() {
		return errors.Errorf("%s is only supported with the native storage backends (%q, %q, %q, %q, %q), but %s is %q; "+
			"either switch to a native backend or disable %s",
			standaloneName,
			server_structs.OriginStoragePosixv2, server_structs.OriginStorageS3v2, server_structs.OriginStorageHTTPSv2,
			server_structs.OriginStorageGlobusv2, server_structs.OriginStorageSSH,
			param.Origin_StorageType.GetName(), storageType, standaloneName)
	}

	// Co-locating a federation service with an origin that refuses to talk to
	// any federation service is contradictory; the co-located module would
	// advertise a federation the origin is not part of.
	for _, module := range []server_structs.ServerType{
		server_structs.DirectorType, server_structs.RegistryType,
		server_structs.CacheType, server_structs.BrokerType,
	} {
		if currentServers.IsEnabled(module) {
			return errors.Errorf("%s cannot be combined with the %s module in the same process; "+
				"run the standalone origin on its own, or disable %s",
				standaloneName, strings.ToLower(module.String()), standaloneName)
		}
	}

	// DisableDirectClients requires that every request carry a token minted by
	// the federation.  A standalone origin has no federation, so the only
	// clients it can ever have are direct ones.
	if param.Origin_DisableDirectClients.GetBool() {
		return errors.Errorf("%s cannot be combined with %s=true: a standalone origin is reached only by direct clients, "+
			"so every request would be rejected",
			standaloneName, param.Origin_DisableDirectClients.GetName())
	}

	// A discovery URL names the federation this origin belongs to; a standalone
	// origin belongs to none and publishes its own metadata at its own root
	// (see origin.RegisterStandaloneFederationMetadata).  Honouring both would
	// leave the process holding two different answers to "what federation is
	// this?": GetFederation would describe the remote one while every client
	// reading /.well-known/pelican-configuration here is told otherwise.
	//
	// Only an explicitly configured value is an error.  The osdf-flavored binary
	// defaults this parameter to the OSDF's discovery host, and an operator who
	// never asked for a federation should not have to unset something they did
	// not set.
	if discoveryUrl := param.Federation_DiscoveryUrl.GetString(); discoveryUrl != "" && !isDefaultSource(param.Federation_DiscoveryUrl.GetName()) {
		return errors.Errorf("%s cannot be combined with %s=%q: a standalone origin belongs to no federation and "+
			"publishes its own federation metadata; unset %s, or disable %s to join the federation it names",
			standaloneName, param.Federation_DiscoveryUrl.GetName(), discoveryUrl,
			param.Federation_DiscoveryUrl.GetName(), standaloneName)
	}

	// Without a director there is no redirect, so every export is mounted at its
	// bare federation prefix (see origin_serve.RegisterHandlers).  A "/" export
	// therefore claims the whole URL space, including the /api and /.well-known
	// routes the origin's own web UI and discovery document occupy.  Gin panics
	// on that route collision while the server is coming up, far past the point
	// where the operator can be told what is actually wrong.
	for _, export := range configuredFederationPrefixes() {
		if path.Clean(export.prefix) == "/" {
			return errors.Errorf("%s cannot export the root federation prefix %q (configured via %s): a standalone origin "+
				"serves each export at its bare federation prefix, so the root would take over the paths its own web UI "+
				"and /.well-known metadata occupy; pick a non-root prefix such as \"/data\"",
				standaloneName, export.prefix, export.source)
		}
	}

	// Director tests are initiated by a director that will never learn this
	// origin exists.  Turn the knob off rather than leaving the origin's health
	// status permanently critical on a test that can never arrive.
	if param.Origin_DirectorTest.GetBool() {
		log.Warningf("%s may not be enabled when %s is true (no director will ever run the test). Turning off...",
			param.Origin_DirectorTest.GetName(), standaloneName)
		if err := param.Origin_DirectorTest.Set(false); err != nil {
			return err
		}
	}

	// The broker exists to punch through a firewall on behalf of a cache the
	// director sent here; with no federation there is nobody on the other end of
	// the reverse connection, and launchers/launcher.go never starts the
	// listener.  Say so rather than leaving the operator believing it is on.
	if param.Origin_EnableBroker.GetBool() {
		log.Warningf("%s may not be enabled when %s is true (there is no federation broker to connect to). Turning off...",
			param.Origin_EnableBroker.GetName(), standaloneName)
		if err := param.Origin_EnableBroker.Set(false); err != nil {
			return err
		}
	}

	return nil
}

// configuredExportPrefix pairs a federation prefix with the configuration
// parameter that supplied it, so errors can point at the stanza to edit.
type configuredExportPrefix struct {
	source string
	prefix string
}

// configuredFederationPrefixes reports the federation prefixes this origin has
// been told to export.
//
// server_utils.GetOriginExports() is the authority on export parsing, but it
// imports this package and does not run until well after InitServer.  Only the
// prefixes are needed here, so they are read straight from configuration -- and
// from every source rather than only the highest-precedence one, because a
// prefix that cannot work is worth reporting no matter which stanza carries it.
func configuredFederationPrefixes() []configuredExportPrefix {
	prefixes := make([]configuredExportPrefix, 0)

	// The Origin.Exports decode hooks only touch Capabilities and IssuerUrls, so
	// the prefix can be read without them.  A malformed block is left for
	// GetOriginExports to report properly.
	var exports []struct {
		FederationPrefix string `mapstructure:"federationprefix"`
	}
	if err := viper.UnmarshalKey(param.Origin_Exports.GetName(), &exports); err != nil {
		log.Debugf("Unable to read federation prefixes from %s: %v", param.Origin_Exports.GetName(), err)
	}
	for _, export := range exports {
		prefixes = append(prefixes, configuredExportPrefix{source: param.Origin_Exports.GetName(), prefix: export.FederationPrefix})
	}

	// Docker-style "<storage prefix>:<federation prefix>"; a bare value names the
	// same path on both sides.  Split by the same code that builds the exports,
	// so validation cannot disagree with it about where the prefix begins.
	for _, volume := range param.Origin_ExportVolumes.GetStringSlice() {
		_, federationPrefix := server_structs.ParseExportVolume(volume)
		prefixes = append(prefixes, configuredExportPrefix{
			source: param.Origin_ExportVolumes.GetName(),
			prefix: federationPrefix,
		})
	}

	if fedPrefix := param.Origin_FederationPrefix.GetString(); fedPrefix != "" {
		prefixes = append(prefixes, configuredExportPrefix{source: param.Origin_FederationPrefix.GetName(), prefix: fedPrefix})
	}

	return prefixes
}
