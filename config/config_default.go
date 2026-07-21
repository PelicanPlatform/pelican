//go:build !linux

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

package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/param"
)

// osShortRuntimeTempBase returns the base directory ensureRuntimeDir should
// hand to os.MkdirTemp on this OS. Empty means "let os.MkdirTemp default to
// os.TempDir()".
//
// On darwin, $TMPDIR is a per-user path like
// /var/folders/xx/yyyyyyyyyyyyyy/T/, which by itself eats ~35 bytes of the
// 104-byte AF_UNIX socket-path limit. XRootD's admin path adds another
// "pelican-xrootd-<random>/xrootd/<role>/<role>/.xrd/socket" on top, going
// past the limit. Use /tmp instead so the runtime tree is smaller.
//
// On Windows, no such AF_UNIX limit applies and os.TempDir() is fine.
func osShortRuntimeTempBase() string {
	if runtime.GOOS == "darwin" {
		return "/tmp"
	}
	return ""
}

// ApplyOSDefaultsOverride rebases the xrootd runtime sub-path defaults when
// the generated $XDG_RUNTIME_DIR env var is empty, which leaves config paths
// starting with "/pelican/...".
//
//   - client commands never call this and don't compute any of these paths;
//   - the server picks runtimeDir first (whether from XDG, MkdirTemp, or an
//     operator-configured value), and this function just re-anchors sub-path
//     defaults to that same runtimeDir.
//
// A sub-path is only rewritten when both:
//
//  1. its value's source is SourceDefault (i.e. the operator did not set
//     it themselves).
//  2. XDG_RUNTIME_DIR is empty in the process environment. If XDG_RUNTIME_DIR
//     is set then we use it.
//
// Cache.StorageLocation is intentionally NOT anchored under runtimeDir when
// runtimeDir is ephemeral -- the cache backing store must survive restarts.
// On non-Linux we redirect it to os.UserCacheDir()/pelican/cache instead.
func ApplyOSDefaultsOverride(v *viper.Viper, runtimeDir string) {
	if runtimeDir == "" {
		return
	}
	if os.Getenv("XDG_RUNTIME_DIR") != "" {
		return
	}
	st := GetSourceTracker()
	isDefaultSourced := func(paramName string) bool {
		src, has := st.Get(strings.ToLower(paramName))
		return !has || src.Type == SourceDefault
	}
	rebase := func(paramName, newValue string) {
		// Consult the SourceTracker: only overwrite when the current
		// value is default-sourced.
		if !isDefaultSourced(paramName) {
			return
		}
		v.SetDefault(paramName, newValue)
	}
	// Sub-paths that belong under the ephemeral runtime dir. AF_UNIX socket
	// paths are 104 bytes on macOS, so keep the layout shallow.
	rebase(param.Origin_RunLocation.GetName(), filepath.Join(runtimeDir, "xrootd", "origin"))
	rebase(param.Cache_RunLocation.GetName(), filepath.Join(runtimeDir, "xrootd", "cache"))
	rebase(param.LocalCache_RunLocation.GetName(), filepath.Join(runtimeDir, "localcache"))
	rebase(param.Origin_GlobusConfigLocation.GetName(), filepath.Join(runtimeDir, "xrootd", "origin", "globus"))

	// Persistent cache backing store: os.UserCacheDir on macOS resolves to
	// ~/Library/Caches, on Windows to %LocalAppData%. Fall back to the
	// runtime dir if the OS refuses to tell us a persistent location.
	persistCache := filepath.Join(runtimeDir, "cache")
	if cache, err := os.UserCacheDir(); err == nil {
		persistCache = filepath.Join(cache, "pelican", "cache")
	}
	rebase(param.Cache_StorageLocation.GetName(), persistCache)

	// Cache.StorageLocation feeds three interpolated defaults that
	// ApplyDerivedDefaults resolved earlier from the collapsed
	// "/pelican/cache" value: DataLocations, MetaLocations, and
	// NamespaceLocation. Re-derive them from the just-rewritten
	// Cache.StorageLocation so the whole cache tree lives under the
	// same rebased root. Same SourceTracker guard as above.
	// (${Cache.StorageLocation}/{data,meta,namespace}).
	if isDefaultSourced(param.Cache_DataLocations.GetName()) {
		v.SetDefault(param.Cache_DataLocations.GetName(), []string{filepath.Join(persistCache, "data")})
	}
	if isDefaultSourced(param.Cache_MetaLocations.GetName()) {
		v.SetDefault(param.Cache_MetaLocations.GetName(), []string{filepath.Join(persistCache, "meta")})
	}
	if isDefaultSourced(param.Cache_NamespaceLocation.GetName()) {
		v.SetDefault(param.Cache_NamespaceLocation.GetName(), filepath.Join(persistCache, "namespace"))
	}
}

func InitServerOSDefaults(v *viper.Viper) error {
	// Windows / Mac don't have a default set of CAs installed at
	// a well-known location as is expected by XRootD. We want to always generate our own CA
	// if Server_TLSCertificateChain (host certificate chain) is not explicitly set so that
	// we can sign our host cert by our CA instead of self-signing
	tlscaFile := filepath.Join(v.GetString(param.ConfigBase.GetName()), "certificates", "tlsca.pem")
	v.SetDefault(param.Server_TLSCACertificateFile.GetName(), tlscaFile)

	// Use the same CA key filename as the generated default in parameters.yaml
	// (and as Linux, which relies solely on that default). Diverging here — e.g.
	// "tlscakey.pem" — is fragile: this override is applied during
	// SetServerDefaults, but the generated default ("tlsca.key") is (re)applied
	// at InitConfig time via SetParameterDefaults/ApplyDerivedDefaults. Any
	// config re-initialization would then revert Server.TLSCAKey to the
	// generated value, leaving it pointing at a path where no key was written
	// (the CA key having been generated under the diverging name). Keeping the
	// names identical makes the value stable across every init path.
	tlscaKeyFile := filepath.Join(v.GetString(param.ConfigBase.GetName()), "certificates", "tlsca.key")
	v.SetDefault(param.Server_TLSCAKey.GetName(), tlscaKeyFile)

	if err := os.MkdirAll(filepath.Dir(tlscaFile), 0755); err != nil {
		return err
	}

	// Note: creating an empty file is insufficient for XRootD
	/*
		fp, err := os.OpenFile(tlscaFile, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			return err
		}
		defer fp.Close()
	*/
	return nil
}
