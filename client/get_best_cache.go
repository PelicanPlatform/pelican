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
	"bytes"
	"errors"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

func GetBestCache(cacheListName string) ([]string, error) {

	if cacheListName == "" {
		cacheListName = "xroot"
	}

	GeoIpUrl := url.URL{}
	// Use the geo ip service on the WLCG Web Proxy Auto Discovery machines
	geo_ip_sites := [...]string{"wlcg-wpad.cern.ch", "wlcg-wpad.fnal.gov"}

	// randomize the geo ip sitess
	rand.Shuffle(len(geo_ip_sites), func(i, j int) {
		geo_ip_sites[i], geo_ip_sites[j] = geo_ip_sites[j], geo_ip_sites[i]
	})

	var caches_list []string
	//Use Stashservers.dat api

	//api_text = "stashservers.dat"
	GeoIpUrl.Path = "stashservers.dat"

	if cacheListName != "" {
		queryParams := GeoIpUrl.Query()
		queryParams.Set("list", cacheListName)
		GeoIpUrl.RawQuery = queryParams.Encode()
	}

	var responselines_b [][]byte

	type header struct {
		Host string
	}

	i := 0

	for i = 0; i < len(geo_ip_sites); i++ {

		cur_site := geo_ip_sites[i]
		var headers header
		headers.Host = cur_site
		log.Debugf("Trying server site of %s", cur_site)

		for _, ip := range getIPs(cur_site) {
			GeoIpUrl.Host = ip
			GeoIpUrl.Scheme = "http"

			// Headers for the HTTP request
			// Create an HTTP client
			var resp *http.Response
			disableProxy := false
			skipResponse := false
			for {
				defaultTransport := http.DefaultTransport.(*http.Transport).Clone()
				if disableProxy {
					log.Debugln("Querying (without proxy)", GeoIpUrl.String())
					defaultTransport.Proxy = nil
				} else {
					log.Debugln("Querying", GeoIpUrl.String())
				}
				client := &http.Client{Transport: defaultTransport}
				req, err := http.NewRequest("GET", GeoIpUrl.String(), nil)
				if err != nil {
					log.Errorln("Failed to create HTTP request:", err)
					skipResponse = true
					break
				}
				req.Header.Add("Cache-control", "max-age=0")
				req.Header.Add("User-Agent", getUserAgent(""))
				resp, err = client.Do(req)
				if err == nil {
					break
				}
				if urle, ok := err.(*url.Error); ok && urle.Unwrap() != nil {
					if ope, ok := urle.Unwrap().(*net.OpError); ok && ope.Op == "proxyconnect" {
						log.Warnln("Failed to connect to proxy; will retry without. ", ope)
						if !disableProxy {
							disableProxy = true
							continue
						}
					}
				}
				log.Errorln("Could not open URL", err)
				skipResponse = true
				break
			}
			if skipResponse {
				continue
			}

			if resp.StatusCode == 200 {
				log.Debugf("Got OK code 200 from %s", cur_site)
				responsetext_b, err := io.ReadAll(resp.Body)
				if err != nil {
					log.Errorln("Could not aquire http response text")
				}
				//responsetext_s := string(responsetext_b)
				//log.Debugln("Recieved from GeoIP server:", responsetext_s)
				responselines_b = bytes.Split(responsetext_b, []byte("\n"))
				defer resp.Body.Close()
				break
			}
		}

		// If we got a response, then stop trying other geoip servers
		if len(responselines_b) > 0 {
			break
		}

	}
	order_str := ""

	if len(responselines_b) > 0 {
		order_str = string(responselines_b[0])
	}

	if order_str == "" {
		if len(caches_list) == 0 {
			log.Errorln("unable to get list of caches")
			return nil, errors.New("Unable to get the list of caches")
		}
		//Unable to find a geo_ip server to user, return random choice from caches
		rand.Shuffle(len(caches_list), func(i, j int) {
			caches_list[i], caches_list[j] = caches_list[j], caches_list[i]
		})
		minsite := caches_list[0]
		log.Debugf("Unable to use Geoip to find closest cache!  Returning random cache %s", minsite)
		log.Debugf("Randomized list of nearest caches: %s", strings.Join(caches_list, ","))
		return caches_list, nil
	} else {
		// The order string should be something like: 3,1,2
		ordered_list := strings.Split(strings.TrimSpace(order_str), ",")
		log.Debugln("Ordered list of caches:", ordered_list)

		//Used the stashservers.dat api
		var err error
		cachesList, err := get_stashservers_caches(responselines_b)

		if err != nil {
			log.Errorln("Error from getting stashcache caches:", err)
			return nil, err
		}

		// Ordered list is an array of index values which are used
		// to index into caches_list
		minIndex, err := strconv.Atoi(ordered_list[0])
		if err != nil {
			log.Errorln("Received a non integer min site from the WPAD servers")
			return nil, errors.New("Received a non integer min site from the WPAD servers")
		}
		minsite := cachesList[cacheListName][minIndex-1]
		log.Debugln("Closest cache:", minsite)

		finalCacheList := make([]string, 0, len(ordered_list))
		for _, ordered_index := range ordered_list {
			orderedIndex, _ := strconv.Atoi(ordered_index)
			finalCacheList = append(finalCacheList, cachesList[cacheListName][orderedIndex-1])
		}

		log.Debugf("Returning closest cache: %s", minsite)
		log.Debugf("Ordered list of nearest caches: %s", finalCacheList)
		return finalCacheList, nil
	}
}
