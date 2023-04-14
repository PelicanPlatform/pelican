package stashcp

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

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
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(geo_ip_sites), func(i, j int) {
		geo_ip_sites[i], geo_ip_sites[j] = geo_ip_sites[j], geo_ip_sites[i]
	})

	var caches_list []string

	// Check if the user provided a caches json file location
	if CachesJsonLocation != "" {
		if _, err := os.Stat(CachesJsonLocation); os.IsNotExist(err) {
			// path does not exist
			log.Errorln(CachesJsonLocation, "does not exist")

			return nil, errors.New("Unable to open caches json file at: " + CachesJsonLocation)
		}

		//Use geo ip api on caches in provided json file
		//caches_list := get_json_caches(caches_json_location)
		var caches_string string = ""

		for _, cache := range caches_list {
			parsed_url, err := url.Parse(cache)
			if err != nil {
				log.Errorln("Could not parse URL")
			}

			caches_string = caches_string + parsed_url.Host

			// Remove the first comma
			caches_string = string([]rune(caches_string)[1:])
			GeoIpUrl.Path = "api/v1.0/geo/stashcp/" + caches_string
		}
	} else {
		//Use Stashservers.dat api

		//api_text = "stashservers.dat"
		GeoIpUrl.Path = "stashservers.dat"

		if cacheListName != "" {
			queryParams := GeoIpUrl.Query()
			queryParams.Set("list", cacheListName)
			GeoIpUrl.RawQuery = queryParams.Encode()
		}
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

		for _, ip := range get_ips(cur_site) {
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
				req.Header.Add("User-Agent", "stashcp/"+Options.Version)
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
		NearestCacheList = caches_list
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

		for _, ordered_index := range ordered_list {
			orderedIndex, _ := strconv.Atoi(ordered_index)
			NearestCacheList = append(NearestCacheList, cachesList[cacheListName][orderedIndex-1])
		}

		log.Debugf("Returning closest cache: %s", minsite)
		log.Debugf("Ordered list of nearest caches: %s", NearestCacheList)
		return NearestCacheList, nil
	}
}

func GetCachesFromDirector(source string, directorUrl string) (caches []Cache, err error) {
	resourceUrl := directorUrl + source

	// Prevent following the Director's redirect
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	log.Debugln("Querying OSDF Director at", resourceUrl)
	resp, err := client.Get(resourceUrl)
	log.Debugln("Director's response:", resp)

	if err != nil {
		log.Errorln("Failed to get response from OSDF Director:", err)
		return
	}

	// A non 307 response status code probably indicates something is wrong with the director
	if resp.StatusCode != 307 {
		err_str := "Unexpected response from Director: " + strconv.Itoa(resp.StatusCode) + ". Either the Director isn't working properly, or the requested namespace doesn't exist (404)"
		err = errors.New(err_str)
		return
	}
	defer resp.Body.Close()

	// Get the Link header
	linkHeader := resp.Header.Values("Link")

	for _, linksStr := range strings.Split(linkHeader[0], ",") {
		links := strings.Split(strings.ReplaceAll(linksStr, " ", ""), ";")

		var endpoint string
		// var rel string // "rel", as defined in the Metalink/HTTP RFC. Currently not being used by
		// the OSDF Client, but is provided by the director.
		var pri int
		for _, val := range links {
			if strings.HasPrefix(val, "<") {
				endpoint = val[1 : len(val)-1]
			} else if strings.HasPrefix(val, "pri") {
				pri, _ = strconv.Atoi(val[4:])
			}
			// } else if strings.HasPrefix(val, "rel") {
			// 	rel = val[5 : len(val)-1]
			// }
		}

		// Construct the cache objects, populating only the url+port that will be used
		// based on authentication. Also, cache.Resource is currently being set as
		// the priority, because the Director at this time doesn't provide a resource
		// name. Maybe there's a way to bake that into the LINK header for each cache
		// while still following Metalink/HTTP?
		var cache Cache
		port := strings.Split(endpoint, ":")[1]
		if port == "8000" {
			cache.Endpoint = endpoint
			cache.AuthEndpoint = "SHOULDNT_BE_USED"
		} else if port == "8443" {
			cache.Endpoint = "SHOULDNT_BE_USED"
			cache.AuthEndpoint = endpoint
		}
		cache.Resource = strconv.Itoa(pri)
		caches = append(caches, cache)
	}

	// Making the assumption that the Link header doesn't already provide the caches
	// in order (even though it probably does). This sorts the caches and ensures
	// we're using the "pri" tag to order them
	sort.Slice(caches, func(i, j int) bool {
		val1, _ := strconv.Atoi(caches[i].Resource)
		val2, _ := strconv.Atoi(caches[j].Resource)
		return val1 < val2
	})

	return caches, err
}
