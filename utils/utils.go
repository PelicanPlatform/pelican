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
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var (
	watermarkUnits = []byte{'k', 'm', 'g', 't'}
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
// It will return empty strings if the provided userAgent fails to match against the parser
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

// Helper function to extract project from User-Agent
// Will return an empty string if no project is found
func ExtractProjectFromUserAgent(userAgents []string) string {
	prefix := "project/"

	for _, userAgent := range userAgents {
		parts := strings.Split(userAgent, " ")
		for _, part := range parts {
			if strings.HasPrefix(part, prefix) {
				return strings.TrimPrefix(part, prefix)
			}
		}
	}

	return ""
}

// Convert map to slice of values
func MapToSlice[K comparable, V any](m map[K]V) []V {
	s := make([]V, 0, len(m))
	for _, v := range m {
		s = append(s, v)
	}
	return s
}

// Function for validating the various types of watermarks we might get from config
//
// In particular, some parameters may be provided as an integer percentage (e.g. 95), or as a byte value with
// a unit suffix (e.g. 100k). We then return the value as an float64 so that the layer calling this function
// can validate relative values of different watermarks (e.g. !(low > high)). The returned float64 is only meant
// to be used for comparing two watermark values, but only if both are either percentages or byte values, as
// indicated by the isAbsolute return value.
func ValidateWatermark(paramName string, requireSuffix bool) (wm float64, isAbsolute bool, err error) {
	wmStr := viper.GetString(paramName)
	if wmStr == "" {
		return 0, false, errors.Errorf("watermark value for config param '%s' is empty.", paramName)
	}

	// If the watermark doesn't parse as a float or we require a suffix, assume it's a byte value
	// and try to validate it as such
	wm, err = strconv.ParseFloat(wmStr, 64)
	if requireSuffix || err != nil {
		suffix := wmStr[len(wmStr)-1]
		valStr := wmStr[:len(wmStr)-1]
		if !slices.Contains(watermarkUnits, suffix) {
			return 0, false, errors.Errorf("watermark value %s for config param '%s' is missing a valid byte suffix (k|m|g|t).", wmStr, paramName)
		}

		val, err := strconv.ParseFloat(valStr, 64)
		if err != nil {
			return 0, false, errors.Wrapf(err, "watermark value %s for config param '%s' is not a valid number.", wmStr, paramName)
		}

		// These all constitute absolute values because they aren't relative to disk size.
		switch suffix {
		case 'k':
			return val * 1024, true, nil
		case 'm':
			return val * 1024 * 1024, true, nil
		case 'g':
			return val * 1024 * 1024 * 1024, true, nil
		case 't':
			return val * 1024 * 1024 * 1024 * 1024, true, nil
		default: // Should never hit this default because of the check above, but can't hurt to set a default
			return 0, false, errors.Errorf("watermark value %s for config param '%s' is missing a valid byte suffix (k|m|g|t).", wmStr, paramName)
		}

	}

	log.Infof("Interpreting watermark value %s for config param '%s' as a percentage.", wmStr, paramName)
	if wm > 100 || wm < 0 {
		return 0, false, errors.Errorf("watermark value %s for config param '%s' must be a valid percentage in the range [0, 100].", wmStr, paramName)
	}

	return wm, false, nil
}
