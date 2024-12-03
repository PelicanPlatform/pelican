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
	// TODO: pull stoage-specific fields into a separate struct and mixin
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
	WarnExportVolumes      string = "Passing export volumes via -v at the command line causes Pelican to ignore exports configured via the yaml file. " +
		"However, namespaces exported this way will inherit the Origin.Enable* settings from your configuration file. " +
		"For finer-grained control of each export, please configure them in your pelican.yaml file via Origin.Exports"
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

func validateExportPaths(storagePrefix string, federationPrefix string) error {
	if storagePrefix == "" || federationPrefix == "" {
		return errors.Wrap(ErrInvalidOriginConfig, "volume mount/ExportVolume paths cannot be empty")
	}
	if err := validateFederationPrefix(federationPrefix); err != nil {
		return errors.Wrapf(err, "invalid federation prefix %s", federationPrefix)
	}
	if err := validateFederationPrefix(storagePrefix); err != nil {
		return errors.Wrapf(err, "invalid storage prefix %s", storagePrefix)
	}
	return nil
}

// Since Federation Prefixes get treated like POSIX filepaths by XRootD and other services, we need to
// validate them to ensure funky things don't ensue
func validateFederationPrefix(prefix string) error {
	if len(prefix) == 0 {
		return errors.Errorf("prefix %s is empty", prefix)
	}

	if !strings.HasPrefix(prefix, "/") {
		return errors.Wrapf(ErrInvalidOriginConfig, "prefix %s must begin with '/'", prefix)
	}
	if strings.Contains(prefix, "//") {
		return errors.Wrapf(ErrInvalidOriginConfig, "prefix %s contains invalid '//' characters", prefix)
	}

	if strings.Contains(prefix, "./") {
		return errors.Wrapf(ErrInvalidOriginConfig, "prefix %s contains invalid './' characters", prefix)
	}

	if strings.Contains(prefix, "..") {
		return errors.Wrapf(ErrInvalidOriginConfig, "prefix %s contains invalid '..' characters", prefix)
	}

	if strings.HasPrefix(prefix, "~") {
		return errors.Wrapf(ErrInvalidOriginConfig, "prefix %s contains begins with invalid '~' character", prefix)
	}

	if strings.Contains(prefix, "$") {
		return errors.Wrapf(ErrInvalidOriginConfig, "prefix %s contains invalid '$' characters", prefix)
	}

	if strings.Contains(prefix, "*") {
		return errors.Wrapf(ErrInvalidOriginConfig, "prefix %s contains invalid '*' characters", prefix)
	}

	if strings.Contains(prefix, `\`) {
		return errors.Wrapf(ErrInvalidOriginConfig, "prefix %s contains invalid '\\' characters", prefix)
	}

	if strings.Contains(prefix, "?") {
		return errors.Wrapf(ErrInvalidOriginConfig, "prefix %s contains invalid '?' characters", prefix)
	}

	if server_structs.IsCacheNS(prefix) || server_structs.IsOriginNS(prefix) {
		return errors.Wrapf(ErrInvalidOriginConfig, "prefix %s is a reserved prefix for cache/origin server registration", prefix)
	}

	return nil
}

// https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html
func validateBucketName(bucket string) error {
	if len(bucket) == 0 { // We treat 0-length bucket names as a special case
		return nil
	} else {
		// However, if there _is_ a bucket name, it must be between 3 and 63 characters
		if len(bucket) < 3 || len(bucket) > 63 {
			return errors.Wrapf(ErrInvalidOriginConfig, "Bucket name %s is not between 3 and 63 characters", bucket)
		}
	}

	// Buckets cannot contain ..
	if strings.Contains(bucket, "..") {
		return errors.Wrapf(ErrInvalidOriginConfig, "Bucket name %s contains invalid '..'", bucket)
	}

	// Buckets must only contain letters, numbers, '.' and '-'
	for _, char := range bucket {
		if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '.' || char == '-') {
			return errors.Wrapf(ErrInvalidOriginConfig, "Bucket name %s contains invalid character %c", bucket, char)
		}
	}

	// Buckets cannot have capital letters
	if strings.ToLower(bucket) != bucket {
		return errors.Wrapf(ErrInvalidOriginConfig, "Bucket name %s contains capital letters", bucket)
	}

	// Buckets must begin with letter or number and end with letter or number
	if !((bucket[0] >= 'a' && bucket[0] <= 'z') || (bucket[0] >= '0' && bucket[0] <= '9')) ||
		!((bucket[len(bucket)-1] >= 'a' && bucket[len(bucket)-1] <= 'z') || (bucket[len(bucket)-1] >= '0' && bucket[len(bucket)-1] <= '9')) {
		return errors.Wrapf(ErrInvalidOriginConfig, "Bucket name %s must begin and end with a letter or number", bucket)
	}

	// Buckets cannot begin with sthree- or sthree-configurator or xn--
	if strings.HasPrefix(bucket, "sthree-") || strings.HasPrefix(bucket, "xn--") {
		return errors.Wrapf(ErrInvalidOriginConfig, "Bucket name %s cannot begin with 'sthree-' or 'sthree-configurator'", bucket)
	}

	// Bucket names cannot end in -s3alias or --ol-s3
	if strings.HasSuffix(bucket, "-s3alias") || strings.HasSuffix(bucket, "--ol-s3") {
		return errors.Wrapf(ErrInvalidOriginConfig, "Bucket name %s cannot end with '-s3alias' or '--ol-s3'", bucket)
	}

	return nil
}

// GetOriginExports is used to parse the config yaml and return a list of OriginExports. It should only touch
// the yaml the first time it's called, and then return the in-memory value on subsequent calls.
// When the configuration is set up using the older single-prefix style of configuration, the function will
// convert those values (such as Origin.FederationPrefix, Origin.StoragePrefix, etc.) into the OriginExports
// struct and return a list of one. Otherwise, we'll base things off the list of exports and ignore the single-prefix
// style of configuration.
func GetOriginExports() ([]OriginExport, error) {
	if originExports != nil {
		return originExports, nil
	}

	viper.SetDefault("Origin.StorageType", "posix")
	storageTypeStr := param.Origin_StorageType.GetString()

	storageType, err := server_structs.ParseOriginStorageType(storageTypeStr)
	if err != nil {
		return originExports, err
	}

	capabilities := server_structs.Capabilities{
		PublicReads: param.Origin_EnablePublicReads.GetBool(),
		Writes:      param.Origin_EnableWrites.GetBool(),
		Listings:    param.Origin_EnableListings.GetBool(),
		Reads:       param.Origin_EnableReads.GetBool() || param.Origin_EnablePublicReads.GetBool(),
		DirectReads: param.Origin_EnableDirectReads.GetBool(),
	}

	var originExport OriginExport
	switch storageType {
	case server_structs.OriginStoragePosix:
		// First, we handle any exports passed via Origin.ExportVolumes to which we've bound all -v entries
		// from the command line. When this option is used for configuration, we'll ignore exports from our
		// pelican.yaml, but the namespaces will inherit any Origin.Enable* settings there.
		// Note that we expect ExportVolumes to be of the form /mnt/foo:/bar, where /mnt/foo is the path in the
		// storage system and /bar is the path in the federation.
		if len(param.Origin_ExportVolumes.GetStringSlice()) > 0 {
			log.Infoln("Configuring exports from export volumes passed via command line or via yaml")
			volumes := param.Origin_ExportVolumes.GetStringSlice()
			tmpExports := make([]OriginExport, len(volumes))
			for idx, volume := range volumes {
				// Perform validation of the namespace
				storagePrefix := filepath.Clean(volume)
				federationPrefix := filepath.Clean(volume)
				volumeMountInfo := strings.SplitN(volume, ":", 2)
				if len(volumeMountInfo) == 2 {
					storagePrefix = filepath.Clean(volumeMountInfo[0])
					federationPrefix = filepath.Clean(volumeMountInfo[1])
				}

				if err = validateExportPaths(storagePrefix, federationPrefix); err != nil {
					return nil, err
				}

				originExport := OriginExport{
					FederationPrefix: federationPrefix,
					StoragePrefix:    storagePrefix,
					Capabilities:     capabilities,
				}
				tmpExports[idx] = originExport
			}

			// If we're only exporting one namespace, we can set the internal Origin.FederationPrefix and Origin.StoragePrefix
			if len(volumes) == 1 {
				viper.Set("Origin.FederationPrefix", tmpExports[0].FederationPrefix)
				viper.Set("Origin.StoragePrefix", tmpExports[0].StoragePrefix)
				viper.Set("Origin.EnableReads", tmpExports[0].Capabilities.Reads)
			}

			log.Warningln(WarnExportVolumes)
			originExports = tmpExports
			return originExports, nil
		}

		// Properly configured Origin.Exports block will unmarshal correctly, so don't loop over anything
		if param.Origin_Exports.IsSet() {
			log.Infoln("Configuring multi-exports from Origin.Exports block in config file")
			var tmpExports []OriginExport
			if err := viper.UnmarshalKey("Origin.Exports", &tmpExports, viper.DecodeHook(StringListToCapsHookFunc())); err != nil {
				return nil, err
			}
			if len(tmpExports) == 0 {
				err := errors.New("Origin.Exports is defined, but no exports were found")
				return nil, err
			} else if len(tmpExports) == 1 {
				// Again, several viper variables might not be set in config. We set them here so that
				// sections of code assuming a single export can make use of them.
				capabilities := tmpExports[0].Capabilities
				reads := capabilities.Reads || capabilities.PublicReads
				viper.Set("Origin.FederationPrefix", (tmpExports)[0].FederationPrefix)
				viper.Set("Origin.StoragePrefix", (tmpExports)[0].StoragePrefix)
				viper.Set("Origin.EnableReads", reads)
				viper.Set("Origin.EnablePublicReads", capabilities.PublicReads)
				viper.Set("Origin.EnableWrites", capabilities.Writes)
				viper.Set("Origin.EnableListings", capabilities.Listings)
				viper.Set("Origin.EnableDirectReads", capabilities.DirectReads)
			}
			for _, export := range tmpExports {
				if err = validateExportPaths(export.StoragePrefix, export.FederationPrefix); err != nil {
					return nil, err
				}
			}
			originExports = tmpExports
			return originExports, nil
		} else { // we're using the simple Origin.FederationPrefix
			log.Infoln("Configuring single-export origin")

			originExport = OriginExport{
				FederationPrefix: param.Origin_FederationPrefix.GetString(),
				StoragePrefix:    param.Origin_StoragePrefix.GetString(),
				Capabilities:     capabilities,
			}

			if err = validateExportPaths(originExport.StoragePrefix, originExport.FederationPrefix); err != nil {
				return nil, err
			}

			viper.Set("Origin.EnableReads", capabilities.Reads)
		}
	case server_structs.OriginStorageHTTPS:
		// clean up the http service URL
		if strings.HasSuffix(param.Origin_HttpServiceUrl.GetString(), "/") {
			log.Warningln("Removing trailing '/' from http service URL")
			viper.Set("Origin.HttpServiceUrl", strings.TrimSuffix(param.Origin_HttpServiceUrl.GetString(), "/"))
		}

		// Handle exports configured via -v or potentially env vars
		if len(param.Origin_ExportVolumes.GetStringSlice()) > 0 {
			log.Infoln("Configuring exports from export volumes passed via command line or via yaml")
			volumes := param.Origin_ExportVolumes.GetStringSlice()
			if len(volumes) > 1 {
				// We don't yet support multiple exports for the HTTPS backend
				return nil, errors.Errorf("https backend does not yet support multiple exports, but %d were provided: %+v", len(volumes), volumes)
			}

			volume := volumes[0]
			// Perform validation of the namespace
			storagePrefix := filepath.Clean(volume)
			federationPrefix := filepath.Clean(volume)
			volumeMountInfo := strings.SplitN(volume, ":", 2)
			if len(volumeMountInfo) == 2 {
				storagePrefix = filepath.Clean(volumeMountInfo[0])
				federationPrefix = filepath.Clean(volumeMountInfo[1])
			}

			if err = validateExportPaths(storagePrefix, federationPrefix); err != nil {
				return nil, err
			}

			// clean up trailing / in the storage prefix
			if strings.HasSuffix(storagePrefix, "/") {
				log.Warningln("Removing trailing '/' from storage prefix", storagePrefix)
				storagePrefix = strings.TrimSuffix(storagePrefix, "/")
			}
			originExport := OriginExport{
				FederationPrefix: federationPrefix,
				StoragePrefix:    storagePrefix,
				Capabilities:     capabilities,
			}

			viper.Set("Origin.FederationPrefix", originExport.FederationPrefix)
			viper.Set("Origin.StoragePrefix", originExport.StoragePrefix)

			log.Warningln(WarnExportVolumes)
			originExports := []OriginExport{originExport}
			return originExports, nil
		}

		if param.Origin_Exports.IsSet() {
			var tmpExports []OriginExport
			if err := viper.UnmarshalKey("Origin.Exports", &tmpExports, viper.DecodeHook(StringListToCapsHookFunc())); err != nil {
				return nil, err
			}
			if len(tmpExports) == 0 {
				err := errors.New("Origin.Exports is defined, but no exports were found")
				return nil, err
			} else if len(tmpExports) > 1 {
				err := errors.New("More than one export found, only one export is currently supported for the https backend")
				return nil, err
			}

			// Assume there's only one export
			export := tmpExports[0]

			// Clean up any path components that might have been added by the user to guarantee the correct
			// URL is constructed without duplicate or missing slashes
			if strings.HasSuffix(export.StoragePrefix, "/") {
				log.Warningln("Removing trailing '/' from storage prefix", export.StoragePrefix)
				export.StoragePrefix = strings.TrimSuffix(export.StoragePrefix, "/")
			}

			if err = validateExportPaths(export.StoragePrefix, export.FederationPrefix); err != nil {
				return nil, err
			}

			capabilities := export.Capabilities
			reads := capabilities.Reads || capabilities.PublicReads
			viper.Set("Origin.FederationPrefix", export.FederationPrefix)
			viper.Set("Origin.StoragePrefix", export.StoragePrefix)
			viper.Set("Origin.EnableReads", reads)
			viper.Set("Origin.EnablePublicReads", capabilities.PublicReads)
			viper.Set("Origin.EnableWrites", capabilities.Writes)
			viper.Set("Origin.EnableListings", capabilities.Listings)
			viper.Set("Origin.EnableDirectReads", capabilities.DirectReads)

			originExports = []OriginExport{export}
			return originExports, nil
		} else { // we're using the simple Origin.FederationPrefix
			log.Infoln("Configuring single-export origin")
			federationPrefix := param.Origin_FederationPrefix.GetString()
			storagePrefix := param.Origin_StoragePrefix.GetString()
			if strings.HasSuffix(storagePrefix, "/") {
				log.Warningln("Removing trailing '/' from storage prefix", storagePrefix)
				storagePrefix = strings.TrimSuffix(storagePrefix, "/")
			}
			originExport = OriginExport{
				FederationPrefix: federationPrefix,
				StoragePrefix:    storagePrefix,
				Capabilities:     capabilities,
			}

			if err = validateExportPaths(originExport.StoragePrefix, originExport.FederationPrefix); err != nil {
				return nil, err
			}
		}
	case server_structs.OriginStorageS3:
		// Handle exports configured via -v or potentially env vars
		if len(param.Origin_ExportVolumes.GetStringSlice()) > 0 {
			log.Infoln("Configuring exports from export volumes passed via command line or via yaml")
			for _, volume := range param.Origin_ExportVolumes.GetStringSlice() {
				// Perform validation of the namespace
				volumeMountInfo := strings.SplitN(volume, ":", 2)
				if len(volumeMountInfo) != 2 {
					// We detected more than one `:` in the volume mount
					return nil, errors.New("Invalid volume mount/ExportVolume format. Each entry must be in the form of my-bucket:/my/prefix")
				}

				bucket := volumeMountInfo[0]
				federationPrefix := filepath.Clean(volumeMountInfo[1])

				if err := validateFederationPrefix(federationPrefix); err != nil {
					return nil, errors.Wrapf(err, "invalid federation prefix for volume %s", volume)
				}
				if err := validateBucketName(bucket); err != nil {
					return nil, errors.Wrapf(err, "invalid bucket name for volume %s", volume)
				}

				if bucket == "" {
					log.Warningf(`The volume mount %s does not contain a bucket. Pelican will interpret this as intending to export all buckets
from S3 service URL. In this configuration, objects can be accessed at /federation/prefix/bucket/object`, volume)
					log.Warningf(`This feature is only compatible with path-style URLs.`)
				}

				originExport := OriginExport{
					FederationPrefix: federationPrefix,
					StoragePrefix:    "/", // TODO: This is a placeholder for now, eventually we want storage prefix to mean something in S3
					S3Bucket:         bucket,
					S3AccessKeyfile:  param.Origin_S3AccessKeyfile.GetString(),
					S3SecretKeyfile:  param.Origin_S3SecretKeyfile.GetString(),
					Capabilities:     capabilities,
				}
				originExports = append(originExports, originExport)
			}

			// If we're only exporting one namespace, we can set the internal Origin.FederationPrefix and Origin.StoragePrefix
			if len(param.Origin_ExportVolumes.GetStringSlice()) == 1 {
				viper.Set("Origin.FederationPrefix", originExports[0].FederationPrefix)
				viper.Set("Origin.S3Bucket", originExports[0].S3Bucket)
				viper.Set("Origin.EnableReads", originExports[0].Capabilities.Reads)
			}

			log.Warningln(WarnExportVolumes)
			return originExports, nil
		}

		if param.Origin_Exports.IsSet() {
			log.Infoln("Configuring multiple S3 exports from Origin.Exports block in config file")
			var tmpExports []OriginExport
			if err := viper.UnmarshalKey("Origin.Exports", &tmpExports, viper.DecodeHook(StringListToCapsHookFunc())); err != nil {
				return nil, errors.Wrap(err, "unable to parse the Origin.Exports configuration")
			}
			if len(tmpExports) == 0 {
				err := errors.New("Origin.Exports is defined, but no exports were found")
				return nil, err
			} else if len(tmpExports) == 1 {
				reads := tmpExports[0].Capabilities.Reads || tmpExports[0].Capabilities.PublicReads
				viper.Set("Origin.FederationPrefix", tmpExports[0].FederationPrefix)
				viper.Set("Origin.StoragePrefix", tmpExports[0].StoragePrefix)
				viper.Set("Origin.S3Bucket", tmpExports[0].S3Bucket)
				viper.Set("Origin.S3AccessKeyfile", tmpExports[0].S3AccessKeyfile)
				viper.Set("Origin.S3SecretKeyfile", tmpExports[0].S3SecretKeyfile)
				viper.Set("Origin.EnableReads", reads)
				viper.Set("Origin.EnablePublicReads", tmpExports[0].Capabilities.PublicReads)
				viper.Set("Origin.EnableWrites", tmpExports[0].Capabilities.Writes)
				viper.Set("Origin.EnableListings", tmpExports[0].Capabilities.Listings)
				viper.Set("Origin.EnableDirectReads", tmpExports[0].Capabilities.DirectReads)
			}

			// Validate each bucket name and federation prefix in the exports
			for _, export := range tmpExports {
				if err := validateFederationPrefix(export.FederationPrefix); err != nil {
					return nil, errors.Wrapf(err, "invalid federation prefix for export %s", export.FederationPrefix)
				}
				if err := validateBucketName(export.S3Bucket); err != nil {
					return nil, errors.Wrapf(err, "invalid bucket name for export %s", export.S3Bucket)
				}
			}
			originExports = tmpExports
			return originExports, nil
		} else { // we're using the simple Origin.FederationPrefix
			log.Infoln("Configuring single-export S3 origin")

			// Validate the federation prefix and bucket names
			if err := validateFederationPrefix(param.Origin_FederationPrefix.GetString()); err != nil {
				return nil, errors.Wrapf(err, "invalid federation prefix for export %s", param.Origin_FederationPrefix.GetString())
			}
			if err := validateBucketName(param.Origin_S3Bucket.GetString()); err != nil {
				return nil, errors.Wrapf(err, "invalid bucket name for export %s", param.Origin_S3Bucket.GetString())
			}

			originExport = OriginExport{
				FederationPrefix: param.Origin_FederationPrefix.GetString(),
				StoragePrefix:    param.Origin_StoragePrefix.GetString(),
				S3Bucket:         param.Origin_S3Bucket.GetString(),
				S3AccessKeyfile:  param.Origin_S3AccessKeyfile.GetString(),
				S3SecretKeyfile:  param.Origin_S3SecretKeyfile.GetString(),
				Capabilities:     capabilities,
			}
			viper.Set("Origin.EnableReads", capabilities.Reads)
		}
	case server_structs.OriginStorageGlobus:
		if len(param.Origin_ExportVolumes.GetStringSlice()) > 0 {
			return nil, errors.New("Globus backend does not support configuring via Origin.ExportVolumes or -v flag. Use Origin.Exports or single export config instead.")
		}

		if param.Origin_Exports.IsSet() {
			log.Infoln("Configuring multiple Globus exports from Origin.Exports block in config file")
			var tmpExports []OriginExport
			if err := viper.UnmarshalKey("Origin.Exports", &tmpExports, viper.DecodeHook(StringListToCapsHookFunc())); err != nil {
				return nil, errors.Wrap(err, "unable to parse the Origin.Exports configuration")
			}
			if len(tmpExports) == 0 {
				err := errors.New("Origin.Exports is defined, but no exports were found")
				return nil, err
			} else if len(tmpExports) == 1 {
				if err := validateFederationPrefix(tmpExports[0].FederationPrefix); err != nil {
					return nil, errors.Wrapf(err, "invalid federation prefix for export %s", tmpExports[0].FederationPrefix)
				}
				reads := tmpExports[0].Capabilities.Reads || tmpExports[0].Capabilities.PublicReads
				viper.Set("Origin.FederationPrefix", tmpExports[0].FederationPrefix)
				viper.Set("Origin.StoragePrefix", "/") // Globus backend does not support StoragePrefix or partial export
				viper.Set(param.Origin_GlobusCollectionID.GetName(), tmpExports[0].GlobusCollectionID)
				viper.Set(param.Origin_GlobusCollectionName.GetName(), tmpExports[0].GlobusCollectionName)
				viper.Set("Origin.EnableReads", reads)
				viper.Set("Origin.EnablePublicReads", tmpExports[0].Capabilities.PublicReads)
				viper.Set("Origin.EnableWrites", tmpExports[0].Capabilities.Writes)
				viper.Set("Origin.EnableListings", tmpExports[0].Capabilities.Listings)
				viper.Set("Origin.EnableDirectReads", tmpExports[0].Capabilities.DirectReads)
			} else { // As of 2024/05/28, we only support one Globus export due to Xrootd restriction
				return nil, fmt.Errorf("Globus storage backend only supports single collection but Origin.Exports has %d", len(tmpExports))
			}

			// TODO: once xrootd supports multiple http servers, come back and allow multiple Globus collections
			// // Multiple exports
			// // Validate each federation prefix in the exports
			// for _, export := range tmpExports {
			// 	if err := validateFederationPrefix(export.FederationPrefix); err != nil {
			// 		return nil, errors.Wrapf(err, "invalid federation prefix for export %s", export.FederationPrefix)
			// 	}
			// 	if export.GlobusCollectionID == "" {
			// 		return nil, errors.Wrapf(err, "invalid GlobusCollectionID %s for export %s: GlobusCollectionID is required", export.GlobusCollectionID, export.FederationPrefix)
			// 	}
			// }
			originExports = tmpExports
			return originExports, nil
		} else { // we're using the simple Origin.FederationPrefix
			log.Infoln("Configuring single-export Globus origin")

			// Validate the federation prefix and bucket names
			if err := validateFederationPrefix(param.Origin_FederationPrefix.GetString()); err != nil {
				return nil, errors.Wrapf(err, "invalid federation prefix for export %s", param.Origin_FederationPrefix.GetString())
			}
			if param.Origin_GlobusCollectionID.GetString() == "" {
				return nil, errors.Wrapf(err, "invalid GlobusCollectionID %s for export %s: GlobusCollectionID is required", param.Origin_GlobusCollectionID.GetString(), param.Origin_FederationPrefix.GetString())
			}

			originExport = OriginExport{
				FederationPrefix:     param.Origin_FederationPrefix.GetString(),
				StoragePrefix:        "/", // Globus backend does not support StoragePrefix or partial export
				GlobusCollectionID:   param.Origin_GlobusCollectionID.GetString(),
				GlobusCollectionName: param.Origin_GlobusCollectionName.GetString(),
				Capabilities:         capabilities,
			}
			viper.Set("Origin.EnableReads", capabilities.Reads)
		}
	case server_structs.OriginStorageXRoot:
		if len(param.Origin_ExportVolumes.GetStringSlice()) > 0 {
			log.Infoln("Configuring exports from export volumes passed via command line or via yaml")
			// This storage backend only works with unauthenticated origins. Check that now.
			if !capabilities.PublicReads {
				return nil, errors.Wrap(ErrInvalidOriginConfig, "the xroot backend requires that Origin.EnablePublicReads is true")
			}

			volumes := param.Origin_ExportVolumes.GetStringSlice()
			tmpExports := make([]OriginExport, len(volumes))
			for idx, volume := range volumes {
				storagePrefix := filepath.Clean(volume)
				federationPrefix := filepath.Clean(volume)
				volumeMountInfo := strings.SplitN(volume, ":", 2)
				if len(volumeMountInfo) == 2 {
					storagePrefix = filepath.Clean(volumeMountInfo[0])
					federationPrefix = filepath.Clean(volumeMountInfo[1])
				}

				if storagePrefix != federationPrefix {
					return nil, errors.Wrapf(ErrInvalidOriginConfig, "federation and storage prefixes must be the same for xroot backends, but you "+
						"provided %s and %s", storagePrefix, federationPrefix)
				}

				if err = validateExportPaths(storagePrefix, federationPrefix); err != nil {
					return nil, err
				}

				originExport := OriginExport{
					FederationPrefix: federationPrefix,
					StoragePrefix:    storagePrefix,
					Capabilities:     capabilities,
				}
				tmpExports[idx] = originExport
			}

			// If we're only exporting one namespace, we can set the internal Origin.FederationPrefix and Origin.StoragePrefix
			if len(volumes) == 1 {
				viper.Set("Origin.FederationPrefix", tmpExports[0].FederationPrefix)
				viper.Set("Origin.StoragePrefix", tmpExports[0].StoragePrefix)
			}

			log.Warningln(WarnExportVolumes)
			originExports = tmpExports

			return originExports, nil
		}

		if param.Origin_Exports.IsSet() {
			log.Infoln("Configuring multi-exports from Origin.Exports block in config file")
			var tmpExports []OriginExport
			if err := viper.UnmarshalKey("Origin.Exports", &tmpExports, viper.DecodeHook(StringListToCapsHookFunc())); err != nil {
				return nil, err
			}
			if len(tmpExports) == 0 {
				err := errors.New("Origin.Exports is defined, but no exports were found")
				return nil, err
			} else if len(tmpExports) == 1 {
				// Again, several viper variables might not be set in config. We set them here so that
				// sections of code assuming a single export can make use of them.
				capabilities := tmpExports[0].Capabilities
				reads := capabilities.Reads || capabilities.PublicReads
				viper.Set("Origin.FederationPrefix", (tmpExports)[0].FederationPrefix)
				viper.Set("Origin.StoragePrefix", (tmpExports)[0].StoragePrefix)
				viper.Set("Origin.EnableReads", reads)
				viper.Set("Origin.EnablePublicReads", capabilities.PublicReads)
				viper.Set("Origin.EnableWrites", capabilities.Writes)
				viper.Set("Origin.EnableListings", capabilities.Listings)
				viper.Set("Origin.EnableDirectReads", capabilities.DirectReads)
			}
			for _, export := range tmpExports {
				if !export.Capabilities.PublicReads {
					return nil, errors.Wrapf(ErrInvalidOriginConfig, "all exports from an xroot backend must have the PublicReads capability, but the export with FederationPrefix "+
						"'%s' did not", export.FederationPrefix)
				}
				// Paths must be the same for the XRoot backend
				if export.StoragePrefix != export.FederationPrefix {
					return nil, errors.Wrapf(ErrInvalidOriginConfig, "federation and storage prefixes must be the same for xroot backends, but you "+
						"provided %s and %s", export.StoragePrefix, export.FederationPrefix)
				}

				if err = validateExportPaths(export.StoragePrefix, export.FederationPrefix); err != nil {
					return nil, err
				}
			}
			originExports = tmpExports
			return originExports, nil
		} else {
			log.Infoln("Configuring single-export origin")
			if !capabilities.PublicReads {
				return nil, errors.Wrap(ErrInvalidOriginConfig, "the xroot backend requires the PublicReads capability, but does not have it")
			}

			originExport = OriginExport{
				FederationPrefix: param.Origin_FederationPrefix.GetString(),
				StoragePrefix:    param.Origin_StoragePrefix.GetString(),
				Capabilities:     capabilities,
			}
			if originExport.StoragePrefix != originExport.FederationPrefix {
				return nil, errors.Wrapf(ErrInvalidOriginConfig, "federation and storage prefixes must be the same for xroot backends, but you "+
					"provided %s and %s", originExport.StoragePrefix, originExport.FederationPrefix)
			}

			if err = validateExportPaths(originExport.StoragePrefix, originExport.FederationPrefix); err != nil {
				return nil, err
			}

			viper.Set("Origin.EnableReads", capabilities.Reads)
		}
	}

	originExports = []OriginExport{originExport}
	return originExports, nil
}

// Generate a test auth token for checking the sentinel location
func generateFileTestScitoken(resourceScope string) (string, error) {
	issuerUrl := param.Server_ExternalWebUrl.GetString()
	if issuerUrl == "" { // if both are empty, then error
		return "", errors.New("failed to create token: invalid iss, Server_ExternalWebUrl is empty")
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
		return "", errors.Wrap(err, "failed to create file test token")
	}

	return tok, nil
}

// Check the sentinel files from Origin.Exports
func CheckOriginSentinelLocations(exports []OriginExport) (ok bool, err error) {
	for _, export := range exports {
		if export.SentinelLocation != "" {
			sentinelPath := path.Clean(export.SentinelLocation)
			if path.Base(sentinelPath) != sentinelPath {
				return false, errors.Errorf("invalid SentinelLocation path for StoragePrefix %s, file must not contain a directory. Got %s", export.StoragePrefix, export.SentinelLocation)
			}

			fullPath := filepath.Join(export.FederationPrefix, sentinelPath)
			tkn, err := generateFileTestScitoken(sentinelPath)
			if err != nil {
				return false, errors.Wrap(err, "Failed to generate self-auth token for sentinel file check")
			}

			sentinelUrl := fmt.Sprintf("%v%v", param.Origin_Url.GetString(), fullPath)
			req, err := http.NewRequest(http.MethodGet, sentinelUrl, nil)
			if err != nil {
				return false, errors.Wrap(err, "Failed to create GET request for sentinel file check")
			}
			req.Header.Set("Authorization", "Bearer "+tkn)

			client := http.Client{Transport: config.GetTransport()}
			resp, err := client.Do(req)
			if err != nil {
				return false, errors.Wrapf(err, "fail to open SentinelLocation %s for StoragePrefix %s. Collection check failed", export.SentinelLocation, export.StoragePrefix)
			}

			if resp.StatusCode != 200 {
				return false, errors.New(fmt.Sprintf("Got non-200 response code %v when checking SentinelLocation %s for StoragePrefix %s", resp.StatusCode, export.SentinelLocation, export.StoragePrefix))
			}
		}
	}
	return true, nil
}

func ResetOriginExports() {
	originExports = nil
}
