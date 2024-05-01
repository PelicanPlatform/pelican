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
	"strings"
	"unicode"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// snakeCaseToCamelCase converts a snake case string to camel case.
func SnakeCaseToCamelCase(input string) string {
	isToUpper := false
	isFirst := true
	return strings.Map(func(r rune) rune {
		if r == '_' {
			isToUpper = true
			return -1
		}
		if isToUpper || isFirst {
			isToUpper = false
			return unicode.ToUpper(r)
		}
		return r
	}, input)
}

// snakeCaseToSnakeCase converts a snake_case string to Snake Case (CamelCase with spaces).
func SnakeCaseToHumanReadable(input string) string {
	words := strings.Split(input, "_")
	for i, word := range words {
		words[i] = cases.Title(language.English).String(word)
	}
	return strings.Join(words, " ")
}

// GetPreferredCaches parses the caches it is given and returns it as a list of url's
func GetPreferredCaches(preferredCaches string) (caches []*url.URL, err error) {
	if preferredCaches != "" {
		cacheList := strings.Split(preferredCaches, ",")
		for _, cache := range cacheList {
			if preferredCacheURL, err := url.Parse(cache); err != nil {
				return nil, errors.Errorf("Unable to parse preferred cache (%s) as URL: %s", cache, err.Error())
			} else {
				caches = append(caches, preferredCacheURL)
				log.Debugln("Preferred cache for transfer:", preferredCacheURL)
			}
		}
	}
	return
}
