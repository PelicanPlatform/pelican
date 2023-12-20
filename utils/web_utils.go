/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
)

type (
	Server struct {
		AuthEndpoint string `json:"auth_endpoint"`
		Endpoint     string `json:"endpoint"`
		Resource     string `json:"resource"`
	}

	CredentialGeneration struct {
		BasePath      string `json:"base_path"`
		Issuer        string `json:"issuer"`
		MaxScopeDepth int    `json:"max_scope_depth"`
		Strategy      string `json:"strategy"`
		VaultIssuer   string `json:"vault_issuer"`
		VaultServer   string `json:"vault_server"`
	}

	Namespace struct {
		Caches               []Server             `json:"caches"`
		Origins              []Server             `json:"origins"`
		CredentialGeneration CredentialGeneration `json:"credential_generation"`
		DirlistHost          string               `json:"dirlisthost"`
		Path                 string               `json:"path"`
		ReadHTTPS            bool                 `json:"readhttps"`
		UseTokenOnRead       bool                 `json:"usetokenonread"`
		PutEndpoint          string               `json:"writebackhost"`
	}

	TopologyNamespacesJSON struct {
		Caches     []Server    `json:"caches"`
		Namespaces []Namespace `json:"namespaces"`
	}
)

// MakeRequest makes an http request with our custom http client. It acts similarly to the http.NewRequest but
// it only takes json as the request data.
func MakeRequest(url string, method string, data map[string]interface{}, headers map[string]string) ([]byte, error) {
	payload, _ := json.Marshal(data)
	req, err := http.NewRequest(method, url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	for key, val := range headers {
		req.Header.Set(key, val)
	}
	tr := config.GetTransport()
	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check HTTP response -- should be 200, else something went wrong
	body, _ := io.ReadAll(resp.Body)
	if method == "POST" && resp.StatusCode != 201 && resp.StatusCode != 200 {
		return body, errors.Errorf("The POST attempt to %s resulted in status code %d", url, resp.StatusCode)
	} else if method != "POST" && resp.StatusCode != 200 {
		return body, errors.Errorf("The %s attempt to %s replied with status code %d", method, url, resp.StatusCode)
	}

	return body, nil
}

// GetTopologyJSON returns the namespaces and caches from OSDF topology
func GetTopologyJSON() (*TopologyNamespacesJSON, error) {
	topoNamespaceUrl := param.Federation_TopologyNamespaceUrl.GetString()
	if topoNamespaceUrl == "" {
		metrics.SetComponentHealthStatus(metrics.DirectorRegistry_Topology, metrics.StatusCritical, "Topology namespaces.json configuration option (`Federation.TopologyNamespaceURL`) not set")
		return nil, errors.New("Topology namespaces.json configuration option (`Federation.TopologyNamespaceURL`) not set")
	}

	req, err := http.NewRequest("GET", topoNamespaceUrl, nil)
	if err != nil {
		metrics.SetComponentHealthStatus(metrics.DirectorRegistry_Topology, metrics.StatusCritical, "Failure when getting OSDF namespace data from topology")
		return nil, errors.Wrap(err, "Failure when getting OSDF namespace data from topology")
	}

	req.Header.Set("Accept", "application/json")

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		metrics.SetComponentHealthStatus(metrics.DirectorRegistry_Topology, metrics.StatusCritical, "Failure when getting response for OSDF namespace data")
		return nil, errors.Wrap(err, "Failure when getting response for OSDF namespace data")
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		metrics.SetComponentHealthStatus(metrics.DirectorRegistry_Topology, metrics.StatusCritical, fmt.Sprintf("Error response %v from OSDF namespace endpoint: %v", resp.StatusCode, resp.Status))
		return nil, fmt.Errorf("Error response %v from OSDF namespace endpoint: %v", resp.StatusCode, resp.Status)
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		metrics.SetComponentHealthStatus(metrics.DirectorRegistry_Topology, metrics.StatusCritical, "Failure when reading OSDF namespace response")
		return nil, errors.Wrap(err, "Failure when reading OSDF namespace response")
	}

	var namespaces TopologyNamespacesJSON
	if err = json.Unmarshal(respBytes, &namespaces); err != nil {
		metrics.SetComponentHealthStatus(metrics.DirectorRegistry_Topology, metrics.StatusCritical, fmt.Sprintf("Failure when parsing JSON response from topology URL %v", topoNamespaceUrl))
		return nil, errors.Wrapf(err, "Failure when parsing JSON response from topology URL %v", topoNamespaceUrl)
	}

	metrics.SetComponentHealthStatus(metrics.DirectorRegistry_Topology, metrics.StatusOK, "")

	return &namespaces, nil
}
