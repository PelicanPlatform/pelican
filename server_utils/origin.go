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
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

var originExports *[]OriginExport

type (
	OriginExport struct {
		StoragePrefix    string
		FederationPrefix string
		Capabilities     server_structs.Capabilities
		SentinelLocation string
	}
)

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

// GetOriginExports is used to parse the config yaml and return a list of OriginExports. It should only touch
// the yaml the first time it's called, and then return the cached value on subsequent calls.
// When the configuration is set up using the older single-prefix style of configuration, the function will
// convert those values (such as Origin.FederationPrefix, Origin.StoragePrefix, etc.) into the OriginExports
// struct and return a list of one. Otherwise, we'll base things off the list of exports and ignore the single-prefix
// style of configuration.
func GetOriginExports() (*[]OriginExport, error) {
	if originExports != nil {
		return originExports, nil
	}

	originExports = &[]OriginExport{}

	viper.SetDefault("Origin.StorageType", "posix")
	StorageType := param.Origin_StorageType.GetString()
	switch StorageType {
	case "posix":
		// First, we handle any exports passed via Origin.ExportVolumes to which we've bound all -v entries
		// from the command line. When this option is used for configuration, we'll ignore exports from our
		// pelican.yaml, but the namespaces will inherit any Origin.Enable* settings there.
		// Note that we expect ExportVolumes to be of the form /mnt/foo:/bar, where /mnt/foo is the path in the
		// storage system and /bar is the path in the federation.
		if len(param.Origin_ExportVolumes.GetStringSlice()) > 0 {
			log.Infoln("Configuring exports from export volumes passed via command line or via yaml")
			for _, volume := range param.Origin_ExportVolumes.GetStringSlice() {
				// Perform validation of the namespace
				volumeMountInfo := strings.SplitN(volume, ":", 2)
				if len(volumeMountInfo) != 2 {
					// We detected more than one `:` in the volume mount
					return nil, errors.New("Invalid volume mount/ExportVolume format. Each entry must be in the form of /mnt/foo:/bar")
				}
				storagePrefix := filepath.Clean(volumeMountInfo[0])
				federationPrefix := filepath.Clean(volumeMountInfo[1])

				if !strings.HasPrefix(storagePrefix, "/") || !strings.HasPrefix(federationPrefix, "/") {
					return nil, errors.New(fmt.Sprintf("Volume mount/ExportVolume paths must be absolute and begin with '/', but you provided %s:%s", storagePrefix, federationPrefix))
				}

				if storagePrefix == "" || federationPrefix == "" {
					return nil, errors.New("Volume mount/ExportVolume paths cannot be empty")
				}

				reads := param.Origin_EnableReads.GetBool() || param.Origin_EnablePublicReads.GetBool()
				originExport := OriginExport{
					FederationPrefix: federationPrefix,
					StoragePrefix:    storagePrefix,
					Capabilities: server_structs.Capabilities{
						PublicReads: param.Origin_EnablePublicReads.GetBool(),
						Writes:      param.Origin_EnableWrites.GetBool(),
						Listings:    param.Origin_EnableListings.GetBool(),
						Reads:       reads,
						DirectReads: param.Origin_EnableDirectReads.GetBool(),
					},
				}
				*originExports = append(*originExports, originExport)
			}

			// If we're only exporting one namespace, we can set the internal Origin.FederationPrefix and Origin.StoragePrefix
			if len(param.Origin_ExportVolumes.GetStringSlice()) == 1 {
				viper.Set("Origin.FederationPrefix", (*originExports)[0].FederationPrefix)
				viper.Set("Origin.StoragePrefix", (*originExports)[0].StoragePrefix)
				viper.Set("Origin.EnableReads", (*originExports)[0].Capabilities.Reads)
			}

			log.Warningln("Passing export volumes via -v at the command line causes Pelican to ignore exports configured via the yaml file")
			log.Warningln("However, namespaces exported this way will inherit the Origin.Enable* settings from your configuration")
			log.Warningln("For finer-grained control of each export, please configure them in your pelican.yaml file via Origin.Exports")
			return originExports, nil
		}

		// Properly configured Origin.Exports block will unmarshal correctly, so don't loop over anything
		if param.Origin_Exports.IsSet() {
			log.Infoln("Configuring multi-exports from origin Exports block in config file")
			if err := viper.UnmarshalKey("Origin.Exports", originExports, viper.DecodeHook(StringListToCapsHookFunc())); err != nil {
				return nil, err
			}
			if len(*originExports) == 0 {
				err := errors.New("Origin.Exports is defined, but no exports were found")
				return nil, err
			} else if len(*originExports) == 1 {
				// Again, several viper variables might not be set in config. We set them here so that
				// sections of code assuming a single export can make use of them.
				reads := (*originExports)[0].Capabilities.Reads || (*originExports)[0].Capabilities.PublicReads
				viper.Set("Origin.FederationPrefix", (*originExports)[0].FederationPrefix)
				viper.Set("Origin.StoragePrefix", (*originExports)[0].StoragePrefix)
				viper.Set("Origin.EnableReads", reads)
				viper.Set("Origin.EnablePublicReads", (*originExports)[0].Capabilities.PublicReads)
				viper.Set("Origin.EnableWrites", (*originExports)[0].Capabilities.Writes)
				viper.Set("Origin.EnableListings", (*originExports)[0].Capabilities.Listings)
				viper.Set("Origin.EnableDirectReads", (*originExports)[0].Capabilities.DirectReads)
			}
		} else { // we're using the simple Origin.FederationPrefix
			log.Infoln("Configuring single-export origin")

			reads := (param.Origin_EnableReads.GetBool() || param.Origin_EnablePublicReads.GetBool())
			originExport := OriginExport{
				FederationPrefix: param.Origin_FederationPrefix.GetString(),
				StoragePrefix:    param.Origin_StoragePrefix.GetString(),
				Capabilities: server_structs.Capabilities{
					PublicReads: param.Origin_EnablePublicReads.GetBool(),
					Writes:      param.Origin_EnableWrites.GetBool(),
					Listings:    param.Origin_EnableListings.GetBool(),
					Reads:       reads,
					DirectReads: param.Origin_EnableDirectReads.GetBool(),
				},
			}
			viper.Set("Origin.EnableReads", reads)
			*originExports = append(*originExports, originExport)
		}

	case "s3":
		// For now we're only supporting a single export for S3
		// Our "federation prefix" is actually just
		// /<Origin.S3ServiceName>/<Origin.S3Region>/<Origin.S3Bucket>
		reads := (param.Origin_EnableReads.GetBool() || param.Origin_EnablePublicReads.GetBool())

		federationPrefix := filepath.Join("/", param.Origin_S3ServiceName.GetString(),
			param.Origin_S3Region.GetString(), param.Origin_S3Bucket.GetString())
		originExport := OriginExport{
			FederationPrefix: federationPrefix,
			StoragePrefix:    "",
			Capabilities: server_structs.Capabilities{
				PublicReads: param.Origin_EnablePublicReads.GetBool(),
				Writes:      param.Origin_EnableWrites.GetBool(),
				Listings:    param.Origin_EnableListings.GetBool(),
				Reads:       reads,
				DirectReads: param.Origin_EnableDirectReads.GetBool(),
			},
		}

		viper.Set("Origin.FederationPrefix", federationPrefix)
		*originExports = append(*originExports, originExport)
	}

	return originExports, nil
}

func CheckSentinelLocation(exports *[]OriginExport) (ok bool, err error) {
	for _, export := range *exports {
		if export.SentinelLocation != "" {
			sentinelPath := path.Clean(export.SentinelLocation)
			if path.Base(sentinelPath) != sentinelPath {
				return false, errors.Errorf("invalid SentinelLocation path for StoragePrefix %s, file must not contain a directory. Got %s", export.StoragePrefix, export.SentinelLocation)
			}
			fullPath := filepath.Join(export.StoragePrefix, sentinelPath)
			_, err := os.Stat(fullPath)
			if err != nil {
				return false, errors.Wrapf(err, "fail to open SentinelLocation %s for StoragePrefix %s. Directory check failed", export.SentinelLocation, export.StoragePrefix)
			}
		}
	}
	return true, nil
}

func ResetOriginExports() {
	originExports = nil
}
