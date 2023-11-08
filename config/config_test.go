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

package config

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pelicanplatform/pelican/param"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

var server *httptest.Server

func TestMain(m *testing.M) {
	// Create a test server
	server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// simuilate long server response
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
		code, err := w.Write([]byte("Success"))
		if err != nil {
			fmt.Printf("Error writing out reponse: %d, %v", code, err)
			os.Exit(1)
		}
	}))
	// Init server to get configs initiallized
	viper.Set("Transport.MaxIdleConns", 30)
	viper.Set("Transport.IdleConnTimeout", time.Second*90)
	viper.Set("Transport.TLSHandshakeTimeout", time.Second*15)
	viper.Set("Transport.ExpectContinueTimeout", time.Second*1)
	viper.Set("Transport.ResponseHeaderTimeout", time.Second*10)

	viper.Set("Transport.Dialer.Timeout", time.Second*1)
	viper.Set("Transport.Dialer.KeepAlive", time.Second*30)
	viper.Set("TLSSkipVerify", true)
	server.StartTLS()
	defer server.Close()
	exitCode := m.Run()
	os.Exit(exitCode)
}

func TestResponseHeaderTimeout(t *testing.T) {
	// Change the viper value of the timeout
	viper.Set("Transport.ResponseHeaderTimeout", time.Millisecond*25)
	setupTransport()
	transport := GetTransport()
	client := &http.Client{Transport: transport}
	// make a request
	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Perform the request and handle the timeout
	_, err = client.Do(req)
	if err != nil {
		// Check if the error is a timeout error
		assert.True(t, strings.Contains(err.Error(), "timeout awaiting response headers"))
	} else {
		t.Fatalf("Test returned no error when there should be")
	}

	viper.Set("Transport.ResponseHeaderTimeout", time.Second*10)
}

func TestDialerTimeout(t *testing.T) {
	// Change the viper value of the timeout
	viper.Set("Transport.Dialer.Timeout", time.Millisecond*25)
	setupTransport()
	transport := GetTransport()
	client := &http.Client{Transport: transport}

	unreachableServerURL := "http://abc123:1000"

	// make a request
	req, err := http.NewRequest("GET", unreachableServerURL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Perform the request and handle the timeout
	_, err = client.Do(req)
	if err != nil {
		// Check if the error is a timeout error
		assert.True(t, strings.Contains(err.Error(), "dial tcp"))
	} else {
		t.Fatalf("Test returned no error when there should be")
	}

	viper.Set("Transport.Dialer.Timeout", time.Second*10)
}

func TestInitConfig(t *testing.T) {
	// Set prefix to OSDF to ensure that config is being set
	testingPreferredPrefix = "OSDF"

	// Create a temp config file to use
	tempCfgFile, err := os.CreateTemp("", "pelican-*.yaml")
	viper.Set("config", tempCfgFile.Name())
	if err != nil {
		t.Fatalf("Failed to make temp file: %v", err)
	}

	InitConfig() // Should set up pelican.yaml, osdf.yaml and defaults.yaml

	// Check if server address is correct by defaults.yaml
	assert.True(t, param.Server_Address.GetString() == "0.0.0.0")
	// Check that Federation Discovery url is correct by osdf.yaml
	assert.True(t, param.Federation_DiscoveryUrl.GetString() == "osg-htc.org")

	viper.Set("Server.Address", "1.1.1.1") // should write to temp config file
	if err := viper.WriteConfigAs(tempCfgFile.Name()); err != nil {
		t.Fatalf("Failed to write to config file: %v", err)
	}
	viper.Reset()
	viper.Set("config", tempCfgFile.Name()) // Set the temp file as the new 'pelican.yaml'
	InitConfig()

	// Check if server address overrides the default
	assert.True(t, param.Server_Address.GetString() == "1.1.1.1")
	viper.Reset()

	//Test if prefix is not set, should not be able to find osdfYaml configuration
	testingPreferredPrefix = ""
	tempCfgFile, err = os.CreateTemp("", "pelican-*.yaml")
	viper.Set("config", tempCfgFile.Name())
	if err != nil {
		t.Fatalf("Failed to make temp file: %v", err)
	}
	InitConfig()
	assert.True(t, param.Federation_DiscoveryUrl.GetString() == "")
}
