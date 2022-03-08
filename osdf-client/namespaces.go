package stashcp

import (
	_ "embed"
	"fmt"
	"strings"

	"gopkg.in/yaml.v2"
)

//go:embed resources/namespaces.yaml
var namespacesYaml []byte

// Namespace holds the structure of stash namespaces
type Namespace struct {
	Path           string `yaml:"path"`
	ReadHTTPS      bool   `yaml:"readhttps"`
	UseTokenOnRead bool   `yaml:"usetokenonread"`
	WriteBackHost  string `yaml:"writebackhost"`
	DirListHost    string `yaml:"dirlisthost"`
}

var namespaces []Namespace

func GetNamespaces() ([]Namespace, error) {
	// Allocate the namespaces
	var ns []Namespace
	err := yaml.Unmarshal(namespacesYaml, &ns)
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
