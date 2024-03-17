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

// Common pacakge contains shared structs and methods between different Pelican pacakges.
package common

import (
	"path/filepath"
	"reflect"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/param"
)

var originExports []OriginExports

type (
	OriginExports struct {
		StoragePrefix    string
		FederationPrefix string
		Capabilities     Capabilities
	}

	OriginStorageType string
)

var (
	ErrUnknownOriginStorageType = errors.New("unknown origin storage type")
	ErrInvalidOriginConfig      = errors.New("invalid origin configuration")
)

const (
	OriginStoragePosix OriginStorageType = "posix"
	OriginStorageS3    OriginStorageType = "s3"
	OriginStorageHTTPS OriginStorageType = "https"
)

// Convert a string to an OriginStorageType
func ParseOriginStorageType(storageType string) (ost OriginStorageType, err error) {
	switch storageType {
	case string(OriginStorageS3):
		ost = OriginStorageS3
	case string(OriginStorageHTTPS):
		ost = OriginStorageHTTPS
	case string(OriginStoragePosix):
		ost = OriginStoragePosix
	default:
		err = errors.Wrapf(ErrUnknownOriginStorageType, "storage type %s (known types are posix, s3, and https)", storageType)
	}
	return
}

/*
A decoder hook we can pass to viper.Unmarshal to convert a list of strings to a struct
with boolean fields. In this case, we're a string slice (flow) from yaml:

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
		if to != reflect.TypeOf(Capabilities{}) {
			return data, nil
		}

		// Convert the slice of interfaces to a slice of strings
		interfaces := data.([]interface{})
		caps := make([]string, len(interfaces))
		for i, v := range interfaces {
			caps[i] = v.(string)
		}

		// Convert the string slice to ExportCapabilities struct
		exportCaps := Capabilities{}
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

	if !strings.HasPrefix(storagePrefix, "/") || !strings.HasPrefix(federationPrefix, "/") {
		return errors.Wrapf(ErrInvalidOriginConfig, "volume mount/ExportVolume paths must be absolute and begin with '/', but %s:%s was provided", storagePrefix, federationPrefix)
	}
	return nil
}

// GetOriginExports is used to parse the config yaml and return a list of OriginExports. It should only touch
// the yaml the first time it's called, and then return the cached value on subsequent calls.
// When the configuration is set up using the older single-prefix style of configuration, the function will
// convert those values (such as Origin.FederationPrefix, Origin.StoragePrefix, etc.) into the OriginExports
// struct and return a list of one. Otherwise, we'll base things off the list of exports and ignore the single-prefix
// style of configuration.
func GetOriginExports() ([]OriginExports, error) {
	if originExports != nil {
		return originExports, nil
	}

	viper.SetDefault("Origin.StorageType", "posix")
	storageTypeStr := param.Origin_StorageType.GetString()

	storageType, err := ParseOriginStorageType(storageTypeStr)
	if err != nil {
		return originExports, err
	}

	capabilities := Capabilities{
		PublicReads: param.Origin_EnablePublicReads.GetBool(),
		Writes:      param.Origin_EnableWrites.GetBool(),
		Listings:    param.Origin_EnableListings.GetBool(),
		Reads:       param.Origin_EnableReads.GetBool() || param.Origin_EnablePublicReads.GetBool(),
		DirectReads: param.Origin_EnableDirectReads.GetBool(),
	}

	var originExport OriginExports
	switch storageType {
	case OriginStoragePosix:
		// First, we handle any exports passed via Origin.ExportVolumes to which we've bound all -v entries
		// from the command line. When this option is used for configuration, we'll ignore exports from our
		// pelican.yaml, but the namespaces will inherit any Origin.Enable* settings there.
		// Note that we expect ExportVolumes to be of the form /mnt/foo:/bar, where /mnt/foo is the path in the
		// storage system and /bar is the path in the federation.
		if len(param.Origin_ExportVolumes.GetStringSlice()) > 0 {
			log.Infoln("Configuring exports from export volumes passed via command line or via yaml")
			volumes := param.Origin_ExportVolumes.GetStringSlice()
			tmpExports := make([]OriginExports, len(volumes))
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

				originExport := OriginExports{
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

			log.Warningln("Passing export volumes via -v at the command line causes Pelican to ignore exports configured via the yaml file")
			log.Warningln("However, namespaces exported this way will inherit the Origin.Enable* settings from your configuration")
			log.Warningln("For finer-grained control of each export, please configure them in your pelican.yaml file")
			originExports = tmpExports
			return originExports, nil
		}

		// Properly configured Origin.Exports block will unmarshal correctly, so don't loop over anything
		if param.Origin_Exports.IsSet() {
			log.Infoln("Configuring multi-exports from origin Exports block in config file")
			var tmpExports []OriginExports
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

			originExport = OriginExports{
				FederationPrefix: param.Origin_FederationPrefix.GetString(),
				StoragePrefix:    param.Origin_StoragePrefix.GetString(),
				Capabilities:     capabilities,
			}

			if err = validateExportPaths(originExport.StoragePrefix, originExport.FederationPrefix); err != nil {
				return nil, err
			}

			viper.Set("Origin.EnableReads", capabilities.Reads)
		}

	case OriginStorageS3:
		// For now we're only supporting a single export for S3
		// Our "federation prefix" is actually just
		// /<Origin.S3ServiceName>/<Origin.S3Region>/<Origin.S3Bucket>
		federationPrefix := filepath.Join("/", param.Origin_S3ServiceName.GetString(),
			param.Origin_S3Region.GetString(), param.Origin_S3Bucket.GetString())
		originExport = OriginExports{
			FederationPrefix: federationPrefix,
			StoragePrefix:    "",
			Capabilities:     capabilities,
		}

		if param.Origin_S3Region.GetString() == "" || param.Origin_S3ServiceName.GetString() == "" ||
			param.Origin_S3ServiceUrl.GetString() == "" {
			return nil, errors.Wrap(ErrInvalidOriginConfig, "The S3 backend is missing configuration options to run properly."+
				" You must specify a region (Origin.S3Region), a service name (Origin.S3ServiceName), and a service URL (S3ServiceUrl)"+
				" via the command line or via your configuration file.")
		}

		viper.Set("Origin.FederationPrefix", federationPrefix)
	case OriginStorageHTTPS:
		// Storage prefix is unused by HTTPS so we put in a dummy value of /
		originExport = OriginExports{
			FederationPrefix: param.Origin_FederationPrefix.GetString(),
			StoragePrefix:    "/",
			Capabilities:     capabilities,
		}

		if err = validateExportPaths("/", originExport.FederationPrefix); err != nil {
			return nil, err
		}
	}

	originExports = []OriginExports{originExport}
	return originExports, nil
}

func ResetOriginExports() {
	originExports = nil
}
