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

package server_utils

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token"
)

var originExports []OriginExport

type (
	// TODO: pull storage-specific fields into a separate struct and mixin
	OriginExport struct {
		StoragePrefix    string `json:"storagePrefix"`
		FederationPrefix string `json:"federationPrefix"`

		// Export fields specific to S3 backend. Other things like
		// S3ServiceUrl, S3Region, etc are kept top-level in the config
		S3Bucket        string `json:"s3Bucket,omitempty"`
		S3AccessKeyfile string `json:"s3AccessKeyfile,omitempty"`
		S3SecretKeyfile string `json:"s3SecretKeyfile,omitempty"`

		// Export fields specific to Globus backend
		GlobusCollectionID   string `json:"globusCollectionID,omitempty"`
		GlobusCollectionName string `json:"globusCollectionName,omitempty"`

		// Capabilities for the export
		Capabilities     server_structs.Capabilities `json:"capabilities"`
		SentinelLocation string                      `json:"sentinelLocation"`
	}
)

var (
	ErrInvalidOriginConfig        = errors.New("invalid origin configuration")
	WarnExportVolumes      string = "Using ExportVolumes from the command line (-v), from env vars or in your config causes Pelican to ignore exports " +
		"configured via 'Origin.Exports' configuration. " +
		"However, namespaces exported this way will inherit the Origin.Enable* settings from your configuration file. " +
		"For finer-grained control of each export, please configure them in your pelican.yaml file via 'Origin.Exports'"
)

/*
A decoder hook we can pass to viper.Unmarshal to convert a list of strings to a struct
with boolean fields. In this case, we're converting a string slice (flow) from yaml:

	Exports:
	  Capabilities: ["PublicReads", "Writes"]

to a struct like:

	ExportCapabilities{
		PublicReads: true,
		Writes: true,
		Listings: false,
	}

Here's a helpful tutorial on how to write these:
https://sagikazarmark.hu/blog/decoding-custom-formats-with-viper/
*/
func StringListToCapsHookFunc() mapstructure.DecodeHookFuncType {
	return func(
		from reflect.Type,
		to reflect.Type,
		data interface{},
	) (interface{}, error) {
		// Check that data is a slice of empty interfaces
		if from.Kind() != reflect.Slice || from.Elem().Kind() != reflect.Interface {
			return data, nil
		}

		// Check that we're decoding to the appropriate struct type
		if to != reflect.TypeOf(server_structs.Capabilities{}) {
			return data, nil
		}

		// Convert the slice of interfaces to a slice of strings
		interfaces := data.([]interface{})
		caps := make([]string, len(interfaces))
		for i, v := range interfaces {
			caps[i] = v.(string)
		}

		// Convert the string slice to ExportCapabilities struct
		exportCaps := server_structs.Capabilities{}
		for _, cap := range caps {
			switch cap {
			case "PublicReads":
				// If we set PublicReads to true, then we must also set Reads to true
				exportCaps.PublicReads = true
				exportCaps.Reads = true
			case "Writes":
				exportCaps.Writes = true
			case "Listings":
				exportCaps.Listings = true
			case "DirectReads":
				exportCaps.DirectReads = true
			case "Reads":
				exportCaps.Reads = true
			default:
				return nil, errors.Errorf("Unknown capability %v", cap)
			}
		}

		return exportCaps, nil
	}
}

func logDetectedExportVolumes() {
	log.Infoln("Configuring exports from ExportVolumes passed via command line, via env vars, or via yaml")
	log.Warningln(WarnExportVolumes)
}

type exportVolume struct {
	storagePrefix    string
	federationPrefix string
}

type Origin interface {
	configureExports(Origin) ([]OriginExport, error)
	validateStoragePrefix(sPrefix string) error

	// handleVolumeMounts is primarily used for configuring exports from the -v flag
	handleVolumeMounts(Origin) error
	handleVolumeMountsExtra() error
	// handleExportsCfg is used for configuring exports from the Origin.Exports block
	handleExportsCfg(Origin) error
	handleExportsExtra() error
	// handleTopLevelCfg is used for configuring a single export from the top-level Origin.FederationPrefix and Origin.StoragePrefix
	handleTopLevelCfg(Origin) error
	handleTopLevelExtra() error
	// validateExports is used for validating the exports configured in the Origin.Exports block.
	// Whether or not the export is configured via the Origin.Exports block, we populate a list of OriginExports
	// internally
	validateExports(Origin) error
	// Validate Extra is passed the export and the number of exports so it can do things like
	// check if a certain field is required for a single export, whether an origin type supports
	// multiple exports.
	validateExtra(*OriginExport, int) error
	// If a single export is configured through non top-level means, we may be able to map some export-specific
	// fields to top-level config. This is useful for things like S3Bucket, S3AccessKeyfile, etc.
	mapSingleExtra()
	Type(Origin) server_structs.OriginStorageType
}

// Base origin struct that all other origin types will inherit from
type BaseOrigin struct {
	Exports []OriginExport
	oCaps   server_structs.Capabilities
}

func (b *BaseOrigin) Type(o Origin) server_structs.OriginStorageType {
	return o.Type(o)
}

// Populate the origin capabilities from the top-level config
// We may use these to define the capabilities of each export
// if they're not set at the export level
func (b *BaseOrigin) populateOriginCaps() {
	pubReads := param.Origin_EnablePublicReads.GetBool()
	b.oCaps = server_structs.Capabilities{
		PublicReads: pubReads,
		Writes:      param.Origin_EnableWrites.GetBool(),
		Listings:    param.Origin_EnableListings.GetBool(),
		Reads:       param.Origin_EnableReads.GetBool() || pubReads,
		DirectReads: param.Origin_EnableDirectReads.GetBool(),
	}
}

// Each origin may have different requirements for these functions. In the event they do,
// those functions should be overridden for the origin-specific struct in the corresponding origin file.
//
// If a particular doesn't override these, the base origin def will run and return nil.
// See interface methods for more info.
func (b *BaseOrigin) validateStoragePrefix(prefix string) error {
	return nil
}
func (b *BaseOrigin) handleVolumeMountsExtra() error {
	return nil
}
func (b *BaseOrigin) handleExportsExtra() error {
	return nil
}
func (b *BaseOrigin) handleTopLevelExtra() error {
	return nil
}
func (b *BaseOrigin) validateExtra(*OriginExport, int) error {
	return nil
}
func (b *BaseOrigin) mapSingleExtra() {}

// Since Federation Prefixes get treated like POSIX filepaths by XRootD and other services, we need to
// validate them to ensure funky things don't ensue.
// Note that this isn't a part of the origin interface because it's not meant to be overridden -- _every_ origin
// should validate federation prefixes the same way because this is a property of the federation.
func validateFederationPrefix(prefix string) error {
	if len(prefix) == 0 {
		return errors.Errorf("prefix '%s' is empty", prefix)
	}

	if !strings.HasPrefix(prefix, "/") {
		return errors.Wrapf(ErrInvalidOriginConfig, "prefix %s must begin with '/'", prefix)
	}

	// We're cautious about characters that carry meaning in POSIX filepaths or in URLs
	illegalChars := []string{"//", "./", "..", "~", "$", "*", `\`, "?", "#", "%"}
	for _, char := range illegalChars {
		if strings.Contains(prefix, char) {
			return errors.Wrapf(ErrInvalidOriginConfig, "prefix %s contains invalid character %s", prefix, char)
		}
	}

	if server_structs.IsCacheNS(prefix) || server_structs.IsOriginNS(prefix) {
		return errors.Wrapf(ErrInvalidOriginConfig, "prefix %s is a reserved prefix for cache/origin server registration", prefix)
	}

	return nil
}

// Handle volume mounts passed via -v. These types of exports take precedence over
// any configured via Origin.Exports or Origin.FederationPrefix/Origin.StoragePrefix
func (b *BaseOrigin) handleVolumeMounts(o Origin) (err error) {
	// Nothing to do here if there are no configured volume mounts
	if len(param.Origin_ExportVolumes.GetStringSlice()) == 0 {
		return
	}

	logDetectedExportVolumes()
	volumes := getVolumes()
	if len(volumes) == 0 {
		return
	}

	tmpExports := make([]OriginExport, len(volumes))
	for idx, v := range volumes {
		// Volume mounts don't have a way to set individual capabilities,
		// so we'll use the top-level configs
		tmpExports[idx] = OriginExport{
			StoragePrefix:    v.storagePrefix,
			FederationPrefix: v.federationPrefix,
			Capabilities:     b.oCaps,
		}
	}
	b.Exports = append(b.Exports, tmpExports...)

	// invoke the incoming origin's handleVolumeMountsExtra method
	return o.handleVolumeMountsExtra()
}

// Handle exports configured directly via Origin.FederationPrefix and Origin.StoragePrefix (and others)
// This takes lowest precedence of the configuration mechanisms
func (b *BaseOrigin) handleTopLevelCfg(o Origin) (err error) {
	// If we find an Origin.Exports block or Origin.ExportVolumes, we'll ignore the top-level Origin.FederationPrefix and
	// Origin.StoragePrefix. In fact, these values may be overridden (if set) in the event len(Origin.Exports) == 1
	if param.Origin_Exports.IsSet() || len(param.Origin_ExportVolumes.GetStringSlice()) > 0 {
		return nil
	}

	log.Infoln("Configuring single-export origin using top-level config from Origin.FederationPrefix and Origin.StoragePrefix")

	sPrefix := param.Origin_StoragePrefix.GetString()
	fPrefix := param.Origin_FederationPrefix.GetString()
	e := OriginExport{
		FederationPrefix: fPrefix,
		StoragePrefix:    sPrefix,
		Capabilities:     b.oCaps,
	}

	b.Exports = append(b.Exports, e)

	// invoke the incoming origin's handleTopLevelExtra methods
	return o.handleTopLevelExtra()
}

// Handle exports from the Origin.Exports block. This is the preferred way to do it, and hopefully
// we can get rid of the others someday!
func (b *BaseOrigin) handleExportsCfg(o Origin) error {
	if !param.Origin_Exports.IsSet() || len(param.Origin_ExportVolumes.GetStringSlice()) > 0 {
		return nil
	}

	log.Infoln("Configuring multi-exports from Origin.Exports block in config file")
	var tmpExports []OriginExport
	if err := viper.UnmarshalKey(param.Origin_Exports.GetName(), &tmpExports, viper.DecodeHook(StringListToCapsHookFunc())); err != nil {
		return errors.Wrap(err, "unable to parse the Origin.Exports configuration")
	}
	if len(tmpExports) == 0 {
		return errors.New("Origin.Exports is defined, but no exports were found")
	}

	b.Exports = append(b.Exports, tmpExports...)

	// invoke the incoming origin's handleExportsExtra method
	return o.handleExportsExtra()
}

// Validate the exports in the constructed []OriginExport slice. This is the last step before we
// return the exports to the caller.
func (b *BaseOrigin) validateExports(o Origin) (err error) {
	if len(b.Exports) == 0 {
		return errors.New("no exports configured")
	}

	// Note that we assume we've already populated the origin export list
	for i := range b.Exports { // validateExtra may update some parts of the export, so we need the index.
		e := &b.Exports[i]
		// all fed prefixes are validated the same way -- no way to override this one!
		if err = validateFederationPrefix(e.FederationPrefix); err != nil {
			return
		}
		// validateStoragePrefix may be overridden by each origin type
		if err = o.validateStoragePrefix(e.StoragePrefix); err != nil {
			return
		}

		// Validate the extra fields for the origin type
		err = o.validateExtra(e, len(b.Exports))
		if err != nil {
			return
		}
	}

	return nil
}

// If we have one export, we may need to set top-level configs (which are mostly deprecated or headed that way), e.g.
// S3Bucket, S3AccessKeyfile, etc.
func (b *BaseOrigin) mapSingleExportIfNeeded(o Origin) {
	if len(b.Exports) != 1 {
		return
	}

	export := b.Exports[0]

	// Map prefixes
	viper.Set(param.Origin_FederationPrefix.GetName(), export.FederationPrefix)
	viper.Set(param.Origin_StoragePrefix.GetName(), export.StoragePrefix)

	// Map capabilities
	viper.Set(param.Origin_EnablePublicReads.GetName(), export.Capabilities.PublicReads)
	viper.Set(param.Origin_EnableReads.GetName(), export.Capabilities.Reads || export.Capabilities.PublicReads)
	viper.Set(param.Origin_EnableWrites.GetName(), export.Capabilities.Writes)
	viper.Set(param.Origin_EnableListings.GetName(), export.Capabilities.Listings)
	viper.Set(param.Origin_EnableDirectReads.GetName(), export.Capabilities.DirectReads)

	// invoke the incoming origin's mapSingleExtra method
	o.mapSingleExtra()
}

// configureExports is the main driver for setting up exports for all different origin types.
// It defines the overall flow and steps required for configuring exports.
func (b *BaseOrigin) configureExports(o Origin) ([]OriginExport, error) {
	// Get the top-level origin caps
	b.populateOriginCaps()

	// Handle any volume mounts passed via -v
	if err := b.handleVolumeMounts(o); err != nil {
		return nil, err
	}

	// Handle anything set top-level in the Origin.XXX config
	if err := b.handleTopLevelCfg(o); err != nil {
		return nil, err
	}

	// Handle exports configured via Origin.Exports
	if err := b.handleExportsCfg(o); err != nil {
		return nil, err
	}

	if err := b.validateExports(o); err != nil {
		return nil, err
	}

	if len(b.Exports) == 0 {
		return nil, errors.New("no exports configured")
	}

	b.mapSingleExportIfNeeded(o)

	return b.Exports, nil
}

// GetOriginExports is the one-stop shop for parsing/configuring origin exports. It should only touch
// the yaml the first time it's called, and then return the in-memory value on subsequent calls.
func GetOriginExports() ([]OriginExport, error) {
	if originExports != nil {
		return originExports, nil
	}

	// This default also set in config.go, but duplicating it here makes testing a bit easier.
	viper.SetDefault("Origin.StorageType", "posix")
	storageType, err := server_structs.ParseOriginStorageType(param.Origin_StorageType.GetString())
	if err != nil {
		return originExports, err
	}

	// Determine origin type and instantiate the appropriate origin struct
	var origin Origin
	switch storageType {
	case server_structs.OriginStoragePosix:
		origin = &PosixOrigin{}
	case server_structs.OriginStorageHTTPS:
		origin = &HTTPSOrigin{}
	case server_structs.OriginStorageS3:
		origin = &S3Origin{}
	case server_structs.OriginStorageGlobus:
		origin = &GlobusOrigin{}
	case server_structs.OriginStorageXRoot:
		origin = &XRootOrigin{}
	default:
		return nil, errors.New("unsupported storage type")
	}

	// Configure the exports for the deduced origin type
	originExports, err = origin.configureExports(origin)
	if err != nil {
		return nil, errors.Wrap(ErrInvalidOriginConfig, err.Error())
	}

	return originExports, nil
}

// Parse the volumes passed via -v flag
func getVolumes() []exportVolume {
	volumes := param.Origin_ExportVolumes.GetStringSlice()
	exportVolumes := make([]exportVolume, len(volumes))
	for idx, volume := range volumes {
		// Perform validation of the namespace
		storagePrefix := filepath.Clean(volume)
		federationPrefix := filepath.Clean(volume)
		volumeMountInfo := strings.SplitN(volume, ":", 2)
		if len(volumeMountInfo) == 2 {
			storagePrefix = filepath.Clean(volumeMountInfo[0])
			federationPrefix = filepath.Clean(volumeMountInfo[1])
		}

		exportVolumes[idx] = exportVolume{
			storagePrefix:    storagePrefix,
			federationPrefix: federationPrefix,
		}
	}
	return exportVolumes
}

// Given a parameter and a file path, validate the file. If the file does not exist
// or can't be read, return an error.
func validateFile(fPath string) error {
	// Check if the file exists
	info, err := os.Stat(fPath)
	if os.IsNotExist(err) {
		return errors.New("file does not exist")
	}

	// Check if the file is a regular file
	if !info.Mode().IsRegular() {
		return errors.New("not a regular file")
	}

	// Check if the file is readable
	file, err := os.Open(fPath)
	if err != nil {
		return errors.Wrap(err, "unable to open file")
	}
	defer file.Close()

	return nil
}

// Generate a minimally scoped auth token that allows the origin
// to query itself for its sentinel file
func generateSentinelReadToken(resourceScope string) (string, error) {
	issuerUrl := param.Server_ExternalWebUrl.GetString()
	if issuerUrl == "" { // if both are empty, then error
		return "", errors.New("failed to create a sentinel check auth token because required configuration 'Server.ExternalWebUrl' is empty")
	}
	fTestTokenCfg := token.NewWLCGToken()
	fTestTokenCfg.Lifetime = time.Minute
	fTestTokenCfg.Issuer = issuerUrl
	fTestTokenCfg.Subject = "origin"
	fTestTokenCfg.Claims = map[string]string{"scope": fmt.Sprintf("storage.read:/%v", resourceScope)}
	// For self-tests, the audience is the server itself
	fTestTokenCfg.AddAudienceAny()

	// CreateToken also handles validation for us
	tok, err := fTestTokenCfg.CreateToken()
	if err != nil {
		return "", errors.Wrap(err, "failed to create sentinel check auth token")
	}

	return tok, nil
}

// Check the sentinel files from Origin.Exports
func CheckOriginSentinelLocations(exports []OriginExport) (ok bool, err error) {
	for _, export := range exports {
		if export.SentinelLocation != "" {
			log.Infof("Checking that sentinel object %v is present for federation prefix %s", export.SentinelLocation, export.FederationPrefix)
			sentinelPath := path.Clean(export.SentinelLocation)
			if path.Base(sentinelPath) != sentinelPath {
				return false, errors.Errorf("invalid SentinelLocation path for federation prefix %s, path must not contain a directory. Got %s", export.FederationPrefix, export.SentinelLocation)
			}

			fullPath := filepath.Join(export.FederationPrefix, sentinelPath)
			tkn, err := generateSentinelReadToken(sentinelPath)
			if err != nil {
				return false, errors.Wrap(err, "failed to generate self-auth token for sentinel object check")
			}

			sentinelUrl, err := url.JoinPath(param.Origin_Url.GetString(), fullPath)
			if err != nil {
				return false, errors.Wrapf(err, "unable fo form sentinel URL for Origin.Url %v, sentinel path %v", param.Origin_Url.GetString(), fullPath)
			}
			req, err := http.NewRequest(http.MethodGet, sentinelUrl, nil)
			if err != nil {
				return false, errors.Wrap(err, "failed to create GET request for sentinel object check")
			}
			req.Header.Set("Authorization", "Bearer "+tkn)

			client := http.Client{Transport: config.GetTransport()}
			resp, err := client.Do(req)
			if err != nil {
				return false, errors.Wrapf(err, "fail to open sentinel object %s for federation prefix %s.", export.SentinelLocation, export.FederationPrefix)
			}

			if resp.StatusCode != 200 {
				return false, errors.New(fmt.Sprintf("got non-200 response code %v when checking sentinel object %s for federation prefix %s", resp.StatusCode, export.SentinelLocation, export.FederationPrefix))
			}
		}
	}
	return true, nil
}

func ResetOriginExports() {
	originExports = nil
}
