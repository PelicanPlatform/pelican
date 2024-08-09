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
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/pelicanplatform/pelican/param"
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

func maskIPv4With24(ip net.IP) (masked string, ok bool) {
	mask := net.CIDRMask(24, 32)
	maskedIP := ip.Mask(mask)
	return maskedIP.String(), true
}

func maskIPv6With64(ip net.IP) (masked string, ok bool) {
	mask := net.CIDRMask(64, 128)
	maskedIP := ip.Mask(mask)
	return maskedIP.String(), true
}

// ApplyIPMask will apply a /24 bit mask to IPv4 addresses and a /64 bit mask to IPv6
// Will return the input string along with ok == false if there is any error while masking
func ApplyIPMask(ipStr string) (maskedIP string, ok bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ipStr, false
	}
	if ip.To4() != nil {
		return maskIPv4With24(ip)
	}

	if ip.To16() != nil {
		return maskIPv6With64(ip)
	}
	return ipStr, false
}

// ExtractAndMaskIP will extract an IP address from a leading "[" and trailing "]".
// Then the function will apply the ApplyIPMask function
func ExtractAndMaskIP(ipStr string) (maskedIP string, ok bool) {
	if strings.HasPrefix(ipStr, "[") && strings.HasSuffix(ipStr, "]") {
		extractedIP := ipStr[1 : len(ipStr)-1]
		return ApplyIPMask(extractedIP)
	} else {
		return ApplyIPMask(ipStr)
	}
}

// ExtractVersionAndServiceFromUserAgent will extract the Pelican version and service from
// the user agent.
// It will return empty strings if the provided userAgent failes to match against the parser
func ExtractVersionAndServiceFromUserAgent(userAgent string) (reqVer, service string) {
	uaRegExp := regexp.MustCompile(`^pelican-[^\/]+\/\d+\.\d+\.\d+`)
	if matches := uaRegExp.MatchString(userAgent); !matches {
		return "", ""
	}

	userAgentSplit := strings.Split(userAgent, "/")
	reqVer = userAgentSplit[1]
	service = (strings.Split(userAgentSplit[0], "-"))[1]
	return reqVer, service
}

func UrlWithFederation(remoteUrl string) (string, error) {
	if param.Federation_DiscoveryUrl.IsSet() {
		parsedUrl, err := url.Parse(remoteUrl)
		if err != nil {
			newErr := errors.New(fmt.Sprintf("error parsing source url: %s", err))
			return "", newErr
		}
		if parsedUrl.Host != "" {
			newErr := errors.New("Source URL should not have a host when the Federation_DiscoveryUrl is set")
			return "", newErr
		}

		parsedUrl.Host = param.Federation_DiscoveryUrl.GetString()
		parsedUrl.Scheme = "pelican"
		return parsedUrl.String(), nil
	}
	return remoteUrl, nil
}
