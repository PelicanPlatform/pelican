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

// Package namespaces implements namespace lookups and matches for legacy [stashcp] and [osdf-client]
// to maintain backward compatibility.
//
// The namespaces package should not be used for any new features Pelican introduces.
//
// [stashcp]: https://github.com/opensciencegrid/stashcp
// [osdf-client]: https://github.com/htcondor/osdf-client
package namespaces

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

// I don't think we actually want pelican to download the namespace every build
// Doesn't make for reproducible builds
// //go:generate curl -s https://topology-itb.opensciencegrid.org/stashcache/namespaces.json -o resources/namespaces.json

//go:embed resources/namespaces.json
var namespacesJson []byte

// defaultCaches is list of caches to use if no caches are specified in the namespace
var defaultCaches = []Cache{}

// namespaces is a global list of namespaces
var namespaces []Namespace

// Cache
type Cache struct {
	AuthEndpoint string `json:"auth_endpoint"`
	Endpoint     string `json:"endpoint"`
	Resource     string `json:"resource"`
}

// Cache information from the Director service
type DirectorCache struct {
	ResourceName string
	EndpointUrl  string
	Priority     int
	AuthedReq    bool
}

// Credential generation information
type CredentialGeneration struct {
	Issuer        *string `json:"issuer"`
	BasePath      *string `json:"base_path"`
	MaxScopeDepth *int    `json:"max_scope_depth"`
	Strategy      *string `json:"strategy"`
	VaultServer   *string `json:"vault_server"`
}

// Namespace holds the structure of stash namespaces
type Namespace struct {
	Caches               []Cache `json:"caches"`
	SortedDirectorCaches []DirectorCache
	Path                 string                `json:"path"`
	CredentialGen        *CredentialGeneration `json:"credential_generation"`
	Issuer               []string              `json:"issuer"`
	ReadHTTPS            bool                  `json:"readhttps"`
	UseTokenOnRead       bool                  `json:"usetokenonread"`
	WriteBackHost        string                `json:"writebackhost"`
	DirListHost          string                `json:"dirlisthost"`
}

// GetCaches returns the list of caches for the namespace
func (ns *Namespace) GetCaches() []Cache {
	if ns.Caches == nil || len(ns.Caches) == 0 {
		return defaultCaches
	}
	return ns.Caches
}

func (ns *Namespace) GetCacheHosts() []string {
	var caches []string
	for _, cache := range ns.GetCaches() {
		host := strings.Split(cache.Endpoint, ":")[0]
		caches = append(caches, host)
	}
	return caches
}

// MatchCaches compares the caches passed in (presumably from an ordered list of caches)
// to the caches for the namespace, and returns the intersection of the two
func (ns *Namespace) MatchCaches(caches []string) []Cache {
	// Get the caches for the namespace
	nsCaches := ns.GetCacheHosts()

	// Find the intersection of the two
	intersectedCaches := intersect(caches, nsCaches)

	// map the intersectedCaches back to the endpoints (with ports)
	var intersectedCachesWithEndpoints []Cache
	// For each of the caches in the intersection
	for _, cache := range intersectedCaches {
		// Match to the caches in the namespace
		for _, nsCache := range ns.GetCaches() {
			host := strings.Split(nsCache.Endpoint, ":")[0]
			if host == cache {
				intersectedCachesWithEndpoints = append(intersectedCachesWithEndpoints, nsCache)
			}
		}
	}
	return intersectedCachesWithEndpoints
}

// intersect returns the intersection of two slices
// in the order of a
func intersect(a, b []string) []string {
	m := make(map[string]bool)
	var intersect []string
	for _, x := range b {
		m[x] = true
	}
	for _, x := range a {
		if _, ok := m[x]; ok {
			intersect = append(intersect, x)
		}
	}
	return intersect
}

type NamespaceFull struct {
	Caches     []Cache     `json:"caches"`
	Namespaces []Namespace `json:"namespaces"`
}

// GetNamespaces returns the list of namespaces
func GetNamespaces(ctx context.Context) ([]Namespace, error) {
	// Allocate the namespaces
	var nsfull NamespaceFull
	// Try downloading the namespaces, if it fails, use the embedded namespaces
	namespacesFromUrl, err := downloadNamespace(ctx)
	if err != nil {
		log.Debugf("Failed to download namespaces: %s", err)
		if config.GetPreferredPrefix() == config.PelicanPrefix {
			return nil, err
		} else {
			log.Debug("Continuing using built-in namespace configuration")
		}
	} else {
		namespacesJson = namespacesFromUrl
	}
	if len(namespacesJson) > 40 {
		log.Debugf("Parsing namespaces: %s ... (%d characters total)",
			strings.ReplaceAll(string(namespacesJson[:40]), "\n", " "),
			len(namespacesJson))
	} else {
		log.Debugln("Parsing namespaces: ", strings.ReplaceAll(string(namespacesJson), "\n", " "))
	}
	err = json.Unmarshal(namespacesJson, &nsfull)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	defaultCaches = nsfull.Caches

	return nsfull.Namespaces, nil
}

// downloadNamespace downloads the namespace information with timeouts
func downloadNamespace(ctx context.Context) ([]byte, error) {
	// Get the namespace url from the environment
	topoNamespaceUrl := param.Federation_TopologyNamespaceUrl.GetString()
	if len(topoNamespaceUrl) == 0 {
		return nil, errors.New("Federation.TopologyNamespaceUrl is not set; unable to locate valid caches")
	}
	log.Debugln("Downloading namespaces information from", topoNamespaceUrl)

	req, err := http.NewRequestWithContext(ctx, "GET", topoNamespaceUrl, nil)
	if err != nil {
		return nil, err
	}
	client := http.Client{Transport: config.GetTransport()}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Errorf("Failed to download namespaces: %s", resp.Status)
		return nil, errors.New("Failed to download namespaces: " + resp.Status)
	}
	var out bytes.Buffer
	_, err = io.Copy(&out, resp.Body)
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// MatchNamespace matches the namespace passed in to the namespaces in the list
func MatchNamespace(ctx context.Context, path string) (Namespace, error) {
	var err error
	if namespaces == nil {
		namespaces, err = GetNamespaces(ctx)
		if err != nil {
			return Namespace{}, err
		}
	}
	var best Namespace
	for _, namespace := range namespaces {
		if strings.HasPrefix(path, namespace.Path) && len(namespace.Path) > len(best.Path) {
			best = namespace
		}
	}
	if best.Path == "" {
		return Namespace{}, errors.New("OSDF namespace not known for path " + path)
	}
	log.Debugln("Selected namespace:", best)
	return best, nil
}
