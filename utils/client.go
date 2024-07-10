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

package utils

import (
	"net/url"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// The available client transfer URL query parameters
type ClientQueryName string

const (
	QueryRecursive        ClientQueryName = "recursive"
	QueryPack             ClientQueryName = "pack"
	QueryDirectRead       ClientQueryName = "directread"
	QuerySkipStat         ClientQueryName = "skipstat"
	QueryPreferPrefetched ClientQueryName = "prefercached"
)

func (q ClientQueryName) String() string {
	return string(q)
}

// This function checks if we have a valid query (or no query) for the transfer URL
func CheckValidQuery(transferUrl *url.URL) (err error) {
	query := transferUrl.Query()
	recursive, hasRecursive := query[QueryRecursive.String()]
	_, hasPack := query[QueryPack.String()]
	directRead, hasDirectRead := query[QueryDirectRead.String()]
	_, hasSkipStat := query[QuerySkipStat.String()]
	_, hasPreferCached := query[QueryPreferPrefetched.String()]

	// If we have both recursive and pack, we should return a failure
	if hasRecursive && hasPack {
		return errors.New("cannot have both recursive and pack query parameters")
	}

	if hasDirectRead && hasPreferCached {
		return errors.New("cannot have both directread and prefercached query parameters")
	}

	// If there is an argument in the directread query param, inform the user this is deprecated and their argument will be ignored
	if hasDirectRead && directRead[0] != "" {
		log.Warnln("Arguments (true/false) for the ?directread query have been deprecated and will be disallowed in a future release. The argument provided will be ignored")
		return nil
	}

	// If there is an argument in the recursive query param, inform the user this is deprecated and their argument will be ignored
	if hasRecursive && recursive[0] != "" {
		log.Warnln("Arguments (true/false) for the ?recursive query have been deprecated and will be disallowed in a future release. The argument provided will be ignored")
		return nil
	}

	// If we have no query, or we have recursive or pack, we are good
	if len(query) == 0 || hasRecursive || hasPack || hasDirectRead || hasSkipStat || hasPreferCached {
		return nil
	}

	return errors.New("invalid query parameter(s) " + transferUrl.RawQuery + " provided in url " + transferUrl.String())
}
