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
	"net"
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

// This function checks if we have a valid query (or no query) for the transfer URL
func CheckValidQuery(transferUrl *url.URL) (err error) {
	query := transferUrl.Query()
	recursive, hasRecursive := query["recursive"]
	_, hasPack := query["pack"]
	directRead, hasDirectRead := query["directread"]

	// If we have both recursive and pack, we should return a failure
	if hasRecursive && hasPack {
		return errors.New("cannot have both recursive and pack query parameters")
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
	if len(query) == 0 || hasRecursive || hasPack || hasDirectRead {
		return nil
	}

	return errors.New("invalid query parameter(s) " + transferUrl.RawQuery + " provided in url " + transferUrl.String())
}

// Applies a \24 bit mask to an IPv4 address
// If the input string isn't an IPv4 address then the input string is returned
func IPv4Mask(ipStr string) string {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return ipStr
	}
	mask := net.CIDRMask(24, 32)
	maskedIP := ip.Mask(mask)
	return maskedIP.String()
}

// Applies a \64 bit mask to an IPv4 address
// If the input string isn't an IPv4 address then the input string is returned
func IPv6Mask(ipStr string) string {
	ip := net.ParseIP(ipStr).To16()
	if ip == nil || ip.To4() != nil {
		return ipStr
	}
	mask := net.CIDRMask(64, 128)
	maskedIP := ip.Mask(mask)
	return maskedIP.String()
}

// MaskIP applies the appropriate subnet mask to the input IP address.
func MaskIP(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		// Invalid IP
		return ipStr
	}

	if ip.To4() != nil {
		// IPv4
		return IPv4Mask(ipStr)
	}

	if ip.To16() != nil {
		// IPv6
		return IPv6Mask(ipStr)
	}

	// Neither
	return ipStr
}
