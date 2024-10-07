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

package pelican_url

import (
	"fmt"
	"net/url"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// Available pelican URL query params
const (
	QueryRecursive    string = "recursive"
	QueryPack         string = "pack"
	QueryDirectRead   string = "directread"
	QuerySkipStat     string = "skipstat"
	QueryPreferCached string = "prefercached"

	PackValueAuto  string = "auto"
	PackValueTar   string = "tar"
	PackValueTarGz string = "tar.gz"
	PackValueTarXz string = "tar.xz"
	PackValueZip   string = "zip"
)

func ParseQuery(query string) (PelicanURLValues, error) {
	values, err := url.ParseQuery(query)
	if err != nil {
		return nil, err
	}

	return PelicanURLValues(values), nil
}

// Like url.Values.Get, this only gets the first value for a given key
func (pvs PelicanURLValues) Get(key string) string {
	if values, ok := pvs[key]; ok {
		return values[0]
	}
	return ""
}

func (pvs PelicanURLValues) Add(key string, val string) {
	pvs[key] = append(pvs[key], val)
}

// Helper function to check if a query parameter is known
func isKnownQueryParam(key string) bool {
	switch key {
	case QueryRecursive, QueryPack, QueryDirectRead, QuerySkipStat, QueryPreferCached:
		return true
	default:
		return false
	}
}

// ValidateQueryParams checks that the query parameters are valid for a Pelican URL. This
// includes checking that query parameters are known (with the option to allow for unknown)
// and that conflicting query parameters are not present.
func (p *PelicanURL) ValidateQueryParams(opts ...ParseOption) error {
	po := &parseOptions{}
	for _, opt := range opts {
		opt(po)
	}

	query := p.Query()
	if len(query) == 0 {
		return nil
	}

	for key, valSlice := range query {
		// Skip length check for unknown parameters
		if !po.allowUnknownQueryParams || isKnownQueryParam(key) {
			if len(valSlice) > 1 {
				return errors.New(fmt.Sprintf("Multiple values for query parameter '%s' are not allowed", key))
			}
		}

		val := valSlice[0]
		switch key {
		case QueryRecursive:
			if val != "" {
				log.Warningln("Values for 'recursive' query parameter have no effect and will be ignored")
			}
		case QueryPack:
			if val != PackValueAuto && val != PackValueTar && val != PackValueTarGz && val != PackValueTarXz && val != PackValueZip {
				if val == "" {
					return errors.New(fmt.Sprintf("Missing value for query parameter '%s'", key))
				}
				return errors.New(fmt.Sprintf("Invalid value for query parameter '%s': %s", key, val))
			}
		case QueryDirectRead, QuerySkipStat, QueryPreferCached:
			if val != "" {
				log.Warningln(fmt.Sprintf("Values for '%s' query parameter have no effect and will be ignored", key))
			}
		default:
			if po.allowUnknownQueryParams {
				log.Warningln(fmt.Sprintf("Unknown query parameter '%s' will be passed along", key))
			} else {
				return errors.New(fmt.Sprintf("Unknown query parameter '%s'", key))
			}
		}
	}

	// Disallow some conflicting query params
	if _, rExists := query[QueryRecursive]; rExists {
		if _, pExists := query[QueryPack]; pExists {
			return errors.New("Cannot have both 'recursive' and 'pack' query parameters")
		}
	}
	if _, dExists := query[QueryDirectRead]; dExists {
		if _, pcExists := query[QueryPreferCached]; pcExists {
			return errors.New("Cannot have both 'directread' and 'prefercached' query parameters")
		}
	}

	return nil
}
