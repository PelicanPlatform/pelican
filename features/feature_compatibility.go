/***************************************************************
*
* Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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

// The code in this file is used for determining feature compatibility between
// client requests and other servers.

package features

import (
	"github.com/hashicorp/go-version"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/utils"
)

// Given a feature and a server ad, determine whether the server supports the feature.
// Return values are ternary to capture cases where we may not know enough information
// to make a decision.
//
// The function uses the feature structs loaded from the version compatibility yaml to
// determine whether the server's version satisfies the feature's constraints.
func ServerSupportsFeature(feature Feature, sAd server_structs.ServerAd) utils.Ternary {
	adVString := sAd.Version
	if adVString == "" {
		return utils.Tern_Unknown
	}

	adVersion, err := version.NewVersion(adVString)
	if err != nil {
		log.Debugf("Error parsing server version of '%s' for feature '%s': %v", sAd.Name, feature.GetName(), err)
		return utils.Tern_Unknown
	}

	// Determine whether to use Origin or Cache constraints based on the server type
	var versionConstraints map[string]FeatureVersionInfo
	switch sAd.Type {
	case server_structs.OriginType.String():
		versionConstraints = feature.Origin
	case server_structs.CacheType.String():
		versionConstraints = feature.Cache
	default:
		log.Debugf("Unsupported server type '%s' for server feature '%s'", sAd.Type, feature.GetName())
		return utils.Tern_Unknown
	}

	// Check if the server's version satisfies any of the feature's version constraints
	for _, versionInfo := range versionConstraints {
		notBefore, err := version.NewVersion(versionInfo.NotBeforePelican)
		if err != nil {
			log.Debugf("Failed to parse lower version bound for feature '%s': %v", feature.GetName(), err)
			continue
		}

		// If NotAfterPelican is empty, treat it as "no upper bound"
		var notAfter *version.Version
		if versionInfo.NotAfterPelican != "" {
			notAfter, err = version.NewVersion(versionInfo.NotAfterPelican)
			if err != nil {
				log.Debugf("Failed to parse upper version bound for feature '%s': %v", feature.GetName(), err)
				continue
			}
		}

		// Check whether the server's version is within the range
		if adVersion.GreaterThanOrEqual(notBefore) && (notAfter == nil || adVersion.LessThanOrEqual(notAfter)) {
			return utils.Tern_True
		}
	}

	return utils.Tern_False
}
