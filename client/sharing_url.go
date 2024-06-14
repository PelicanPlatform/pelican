/***************************************************************
 *
 * Copyright (C) 2024, University of Nebraska-Lincoln
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
	"context"
	"net/url"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
)

func getDirectorFromUrl(objectUrl *url.URL) (string, error) {
	ctx := context.Background()

	fedInfo, err := config.GetFederation(ctx)
	if err != nil {
		return "", err
	}
	configDirectorUrl := fedInfo.DirectorEndpoint
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
			fedInfo, err := config.DiscoverUrlFederation(ctx, discoveryUrl.String())
			if err != nil {
				return "", errors.Wrapf(err, "Failed to discover location of the director for the federation %s", objectUrl.Host)
			}
			if directorUrl = fedInfo.DirectorEndpoint; directorUrl == "" {
				return "", errors.Errorf("Director for the federation %s not discovered", objectUrl.Host)
			}
		}
	} else if objectUrl.Scheme == "osdf" && configDirectorUrl == "" {
		if objectUrl.Host != "" {
			objectUrl.Path = "/" + objectUrl.Host + objectUrl.Path
			objectUrl.Host = ""
		}
		fedInfo, err := config.DiscoverUrlFederation(ctx, "https://osg-htc.org")
		if err != nil {
			return "", errors.Wrap(err, "Failed to discover director for the OSDF")
		}
		if directorUrl = fedInfo.DirectorEndpoint; directorUrl == "" {
			return "", errors.Errorf("Director for the OSDF not discovered")
		}
	} else if objectUrl.Scheme == "" {
		if configDirectorUrl == "" {
			return "", errors.Errorf("Must provide a federation name for path %s (e.g., pelican://osg-htc.org/%s)", objectUrl.Path, objectUrl.Path)
		} else {
			directorUrl = configDirectorUrl
		}
	} else if objectUrl.Scheme != "osdf" {
		return "", errors.Errorf("Unsupported scheme for pelican: %s://", objectUrl.Scheme)
	}
	return directorUrl, nil
}

func CreateSharingUrl(ctx context.Context, objectUrl *url.URL, isWrite bool) (string, error) {
	directorUrl, err := getDirectorFromUrl(objectUrl)
	if err != nil {
		return "", err
	}
	objectUrl.Path = "/" + strings.TrimPrefix(objectUrl.Path, "/")

	log.Debugln("Will query director for path", objectUrl.Path)
	dirResp, err := queryDirector(ctx, "GET", objectUrl.Path, directorUrl)
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
