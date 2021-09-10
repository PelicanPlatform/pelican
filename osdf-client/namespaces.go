package main

import (
	_ "embed"
	"fmt"
	"gopkg.in/yaml.v2"
	"strings"
)

//go:embed namespaces.yaml
var namespaces_yaml []byte

// /ospool/PROTECTED:
//  readhttps: true
//  writebackhost: https://origin-auth2001.chtc.wisc.edu:1094
type Namespace struct {
	Path string `yaml:"path"`
	ReadHTTPS bool `yaml:"readhttps"`
	UseTokenOnRead bool `yaml:"usetokenonread"`
	WriteBackHost string `yaml:"writebackhost"`
	DirListHost	string `yaml:"dirlisthost"`
}

var namespaces []Namespace

func getNamespaces() ([]Namespace, error) {
	// Allocate the namespaces
	var ns []Namespace
	err := yaml.Unmarshal(namespaces_yaml, &ns)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return ns, nil
}

func MatchNamespace(path string) (Namespace, error) {
	var err error
	if namespaces == nil {
		namespaces, err = getNamespaces()
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
