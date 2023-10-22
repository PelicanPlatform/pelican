/***************************************************************
 *
 * Copyright (C) 2023, University of Nebraska-Lincoln
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

package client

import (
	"net/url"
	"strings"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func getDirectorFromUrl(objectUrl *url.URL) (string, error) {
	configDirectorUrl := param.Federation_DirectorUrl.GetString()
	var directorUrl string
	if objectUrl.Scheme == "pelican" {
		if objectUrl.Host == "" {
			if configDirectorUrl == "" {
				return "", errors.New("Must specify (or configure) the federation hostname with the pelican://-style URLs")
			}
			directorUrl = configDirectorUrl
		} else {
			discoveryUrl := url.URL{
				Scheme: "https",
				Host:   objectUrl.Host,
			}
			viper.Set("Federation.DirectorUrl", "")
			viper.Set("Federation.DiscoveryUrl", discoveryUrl.String())
			if err := config.DiscoverFederation(); err != nil {
				return "", errors.Wrapf(err, "Failed to discover location of the director for the federation %s", objectUrl.Host)
			}
			if directorUrl = param.Federation_DirectorUrl.GetString(); directorUrl == "" {
				return "", errors.Errorf("Director for the federation %s not discovered", objectUrl.Host)
			}
		}
	} else if objectUrl.Scheme == "osdf" && configDirectorUrl == "" {
		if objectUrl.Host != "" {
			objectUrl.Path = "/" + objectUrl.Host + objectUrl.Path
			objectUrl.Host = ""
		}
		viper.Set("Federation.DiscoveryUrl", "https://osg-htc.org")
		if err := config.DiscoverFederation(); err != nil {
			return "", errors.Wrap(err, "Failed to discover director for the OSDF")
		}
		if directorUrl = param.Federation_DirectorUrl.GetString(); directorUrl == "" {
			return "", errors.Errorf("Director for the OSDF not discovered")
		}
	} else if objectUrl.Scheme == "" {
		if configDirectorUrl == "" {
			return "", errors.Errorf("Must provide a federation name for path %s (e.g., pelican://osg-htc.org/%s)", objectUrl.Path, objectUrl.Path)
		} else {
			directorUrl = configDirectorUrl
		}
	} else if objectUrl.Scheme != "" {
		return "", errors.Errorf("Unsupported scheme for pelican: %s://", objectUrl.Scheme)
	}
	return directorUrl, nil
}

func CreateSharingUrl(objectUrl *url.URL, isWrite bool) (string, error) {
	directorUrl, err := getDirectorFromUrl(objectUrl)
	if err != nil {
		return "", err
	}
	objectUrl.Path = "/" + strings.TrimPrefix(objectUrl.Path, "/")

	log.Debugln("Will query director for path", objectUrl.Path)
	dirResp, err := QueryDirector(objectUrl.Path, directorUrl)
	if err != nil {
		log.Errorln("Error while querying the Director:", err)
		return "", errors.Wrapf(err, "Error while querying the director at %s", directorUrl)
	}
	namespace, err := CreateNsFromDirectorResp(dirResp)
	if err != nil {
		return "", errors.Wrapf(err, "Unable to parse response from director at %s", directorUrl)
	}

	opts := config.TokenGenerationOpts{Operation: config.TokenSharedRead}
	if isWrite {
		opts.Operation = config.TokenSharedWrite
	}
	token, err := AcquireToken(objectUrl, namespace, opts)
	if err != nil {
		err = errors.Wrap(err, "Failed to acquire token")
	}
	return token, err
}
