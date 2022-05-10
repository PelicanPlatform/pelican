package stashcp

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed resources/namespaces.json
var namespacesJson []byte

// Namespace holds the structure of stash namespaces
type Namespace struct {
	Path           string `json:"path"`
	ReadHTTPS      bool   `json:"readhttps"`
	UseTokenOnRead bool   `json:"usetokenonread"`
	WriteBackHost  string `json:"writebackhost"`
	DirListHost    string `json:"dirlisthost"`
}

var namespaces []Namespace

func GetNamespaces() ([]Namespace, error) {
	// Allocate the namespaces
	var ns []Namespace
	err := json.Unmarshal(namespacesJson, &ns)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return ns, nil
}

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
