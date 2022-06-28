package stashcp

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"os"
	"strings"
)

//go:embed resources/namespaces.json
var namespacesJson []byte

// Namespace holds the structure of stash namespaces
type Namespace struct {
	Caches         []string `json:"caches"`
	Path           string   `json:"path"`
	ReadHTTPS      bool     `json:"readhttps"`
	UseTokenOnRead bool     `json:"usetokenonread"`
	WriteBackHost  string   `json:"writebackhost"`
	DirListHost    string   `json:"dirlisthost"`
}

var defaultCaches = []string{}

// GetCaches returns the list of caches for the namespace
func (ns *Namespace) GetCaches() []string {
	if ns.Caches == nil || len(ns.Caches) == 0 {
		return defaultCaches
	}
	return ns.Caches
}

// MatchCaches compares the caches passed in (presumably from an ordered list of caches)
// to the caches for the namespace, and returns the intersection of the two
func (ns *Namespace) MatchCaches(caches []string) []string {
	// Get the caches for the namespace
	nsCaches := ns.GetCaches()

	// Find the intersection of the two
	return intersect(caches, nsCaches)
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
	Caches     []string    `json:"caches"`
	Namespaces []Namespace `json:"namespaces"`
}

var namespaces []Namespace

// GetNamespaces returns the list of namespaces
func GetNamespaces() ([]Namespace, error) {
	// Allocate the namespaces
	var nsfull NamespaceFull
	// Try downloading the namespaces, if it fails, use the embedded namespaces
	namespacesFromUrl, err := downloadNamespace()
	if err != nil {
		log.Warningf("Failed to download namespaces: %s", err)
	} else {
		namespacesJson = namespacesFromUrl
	}
	log.Debugln("Parsing namespaces: ", string(namespacesJson))
	err = json.Unmarshal(namespacesJson, &nsfull)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return nsfull.Namespaces, nil
}

// downloadNamespace downloads the namespace information with timeouts
func downloadNamespace() ([]byte, error) {
	// Get the namespace url from the environment
	namespaceUrl, gotNamespaceUrl := os.LookupEnv("STASH_NAMESPACE_URL")
	if !gotNamespaceUrl {
		namespaceUrl = "https://topology.opensciencegrid.org/stashcache/namespaces.json"
	}
	resp, err := http.Get(namespaceUrl)
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
func MatchNamespace(path string) (Namespace, error) {
	var err error
	if namespaces == nil {
		namespaces, err = GetNamespaces()
		if err != nil {
			return Namespace{}, err
		}
	}
	for _, namespace := range namespaces {
		if strings.HasPrefix(path, namespace.Path) {
			return namespace, nil
		}
	}
	return Namespace{}, nil
}
