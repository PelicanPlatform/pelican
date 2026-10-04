/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
)

// TestRedactConfigCredentials covers the helper: credential-bearing URLs are
// redacted wherever they sit in the document, and a document without any is
// returned untouched rather than re-marshaled.
func TestRedactConfigCredentials(t *testing.T) {
	doc := []byte(`Cache:
    TieringTargets:
        - MaxSize: 10GB
          ProviderURL: s3://pelican-cache?awssecretkey=SUPERSECRET&region=us-east-1
        - MaxSize: 5GB
          ProviderURL: s3://AKIDEXAMPLE:SUPERSECRET@other-bucket
Origin:
    ObjectProviderURL: azblob://container?sas_token=SUPERSECRET
Server:
    ExternalWebUrl: https://cache.example.org:8443
    TLSKey: /etc/pelican/tls.key
`)
	out, err := redactConfigCredentials(doc)
	require.NoError(t, err)
	text := string(out)
	assert.NotContains(t, text, "SUPERSECRET")
	assert.NotContains(t, text, "AKIDEXAMPLE")
	// Non-secret parts of those URLs, and every other value, survive.
	assert.Contains(t, text, "region=us-east-1")
	assert.Contains(t, text, "other-bucket")
	assert.Contains(t, text, "https://cache.example.org:8443")
	assert.Contains(t, text, "/etc/pelican/tls.key")

	clean := []byte("Server:\n    ExternalWebUrl: https://cache.example.org:8443\n")
	out, err = redactConfigCredentials(clean)
	require.NoError(t, err)
	assert.Equal(t, clean, out, "a document with nothing to redact is returned byte-for-byte")
}

// TestPrintConfigRedactsCredentials drives the real startup dump.  It runs at
// Info level before any component validates its configuration, so it is the
// one place a refused URL would otherwise still reach the log.
func TestPrintConfigRedactsCredentials(t *testing.T) {
	ResetConfig()
	t.Cleanup(ResetConfig)
	hook := test.NewGlobal()
	t.Cleanup(hook.Reset)
	previous := log.GetLevel()
	log.SetLevel(log.InfoLevel)
	t.Cleanup(func() { log.SetLevel(previous) })

	require.NoError(t, param.Cache_TieringTargets.Set([]interface{}{
		map[string]interface{}{
			"ProviderURL": "s3://AKIDEXAMPLE:SUPERSECRET@pelican-cache?region=us-east-1",
			"MaxSize":     "10GB",
		},
	}))

	require.NoError(t, PrintConfig())

	var dump string
	for _, entry := range hook.AllEntries() {
		if strings.Contains(entry.Message, "Pelican Configuration") {
			dump = entry.Message
		}
	}
	require.NotEmpty(t, dump, "the configuration dump should have been logged")
	assert.Contains(t, dump, "pelican-cache", "the target itself is still shown")
	assert.NotContains(t, dump, "SUPERSECRET")
	assert.NotContains(t, dump, "AKIDEXAMPLE")
}
