package stashcp

import (
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	namespaces "github.com/htcondor/osdf-client/v6/namespaces"
	log "github.com/sirupsen/logrus"
)

// Simple parser to that takes a "values" string from a header and turns it
// into a map of key/value pairs
func HeaderParser(values string) (retMap map[string]string) {
	retMap = map[string]string{}

	// Some headers might not have values, such as the
	// X-OSDF-Authorization header when the resource is public
	if values == "" {
		return
	}

	mapPairs := strings.Split(values, ",")
	for _, pair := range mapPairs {
		// Remove any unwanted spaces
		pair = strings.ReplaceAll(pair, " ", "")

		// Break out key/value pairs and put in the map
		split := strings.Split(pair, "=")
		retMap[split[0]] = split[1]
	}

	return retMap
}

// Given the Director response, create the ordered list of caches
// and store it as namespace.SortedDirectorCaches
func CreateNsFromDirectorResp(dirResp *http.Response, namespace *namespaces.Namespace) (err error) {
	xOsdfNamespace := HeaderParser(dirResp.Header.Values("X-Osdf-Namespace")[0])
	namespace.Path = xOsdfNamespace["namespace"]
	namespace.UseTokenOnRead, _ = strconv.ParseBool(xOsdfNamespace["use-token-on-read"])
	namespace.ReadHTTPS, _ = strconv.ParseBool(xOsdfNamespace["readhttps"])

	var xOsdfAuthorization map[string]string
	if len(dirResp.Header.Values("X-Osdf-Authorization")) > 0 {
		xOsdfAuthorization = HeaderParser(dirResp.Header.Values("X-Osdf-Authorization")[0])
		namespace.Issuer = xOsdfAuthorization["issuer"]
	}

	// Create the caches slice
	namespace.SortedDirectorCaches, err = GetCachesFromDirectorResponse(dirResp, namespace.UseTokenOnRead || namespace.ReadHTTPS)
	if err != nil {
		log.Errorln("Unable to construct ordered cache list:", err)
		return
	}
	log.Debugln("Namespace path constructed from Director:", namespace.Path)

	return
}

func QueryDirector(source string, directorUrl string) (resp *http.Response, err error) {
	resourceUrl := directorUrl + source

	// Prevent following the Director's redirect
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	log.Debugln("Querying OSDF Director at", resourceUrl)
	resp, err = client.Get(resourceUrl)
	log.Debugln("Director's response:", resp)

	if err != nil {
		log.Errorln("Failed to get response from OSDF Director:", err)
		return
	}

	defer resp.Body.Close()
	return
}

func GetCachesFromDirectorResponse(resp *http.Response, needsToken bool) (caches []namespaces.DirectorCache, err error) {
	// Get the Link header
	linkHeader := resp.Header.Values("Link")

	for _, linksStr := range strings.Split(linkHeader[0], ",") {
		links := strings.Split(strings.ReplaceAll(linksStr, " ", ""), ";")

		var endpoint string
		// var rel string // "rel", as defined in the Metalink/HTTP RFC. Currently not being used by
		// the OSDF Client, but is provided by the director. Will be useful in the future when 
		// we start looking at cases where we want to duplicate from caches if we're throttling
		// connections to the origin.
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

		// Construct the cache objects, getting endpoint and auth requirements from
		// Director
		var cache namespaces.DirectorCache
		cache.AuthedReq = needsToken
		cache.EndpointUrl = endpoint
		cache.Priority = pri
		caches = append(caches, cache)
	}

	// Making the assumption that the Link header doesn't already provide the caches
	// in order (even though it probably does). This sorts the caches and ensures
	// we're using the "pri" tag to order them
	sort.Slice(caches, func(i, j int) bool {
		val1 := caches[i].Priority
		val2 := caches[j].Priority
		return val1 < val2
	})

	return caches, err
}

// NewTransferDetails creates the TransferDetails struct with the given cache
func NewTransferDetailsUsingDirector(cache namespaces.DirectorCache, https bool) []TransferDetails {
	details := make([]TransferDetails, 0)
	cacheEndpoint := cache.EndpointUrl

	// Form the URL
	cacheURL, err := url.Parse(cacheEndpoint)
	if err != nil {
		log.Errorln("Failed to parse cache:", cache, "error:", err)
		return nil
	}
	if cacheURL.Host == "" {
		// Assume the cache is just a hostname
		cacheURL.Host = cacheEndpoint
		cacheURL.Path = ""
		cacheURL.Scheme = ""
		cacheURL.Opaque = ""
	}
	log.Debugf("Parsed Cache: %s\n", cacheURL.String())
	if https {
		cacheURL.Scheme = "https"
		if !HasPort(cacheURL.Host) {
			// Add port 8444 and 8443
			cacheURL.Host += ":8444"
			details = append(details, TransferDetails{
				Url:   *cacheURL,
				Proxy: false,
			})
			// Strip the port off and add 8443
			cacheURL.Host = cacheURL.Host[:len(cacheURL.Host)-5] + ":8443"
		}
		// Whether port is specified or not, add a transfer without proxy
		details = append(details, TransferDetails{
			Url:   *cacheURL,
			Proxy: false,
		})
	} else {
		cacheURL.Scheme = "http"
		if !HasPort(cacheURL.Host) {
			cacheURL.Host += ":8000"
		}
		isProxyEnabled := IsProxyEnabled()
		details = append(details, TransferDetails{
			Url:   *cacheURL,
			Proxy: isProxyEnabled,
		})
		if isProxyEnabled && CanDisableProxy() {
			details = append(details, TransferDetails{
				Url:   *cacheURL,
				Proxy: false,
			})
		}
	}

	return details
}
