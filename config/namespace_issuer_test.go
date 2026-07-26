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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
)

func TestGetNamespaceIssuerURL(t *testing.T) {
	origExt := param.Server_ExternalWebUrl.GetString()
	origDelegate := param.Origin_DelegateIssuerToDirector.GetBool()
	t.Cleanup(func() {
		_ = param.Server_ExternalWebUrl.Set(origExt)
		_ = param.Origin_DelegateIssuerToDirector.Set(origDelegate)
	})

	// Default (delegation off): the origin's own embedded issuer, with a trailing
	// slash on the external URL correctly trimmed.
	require.NoError(t, param.Server_ExternalWebUrl.Set("https://origin.example:8443/"))
	require.NoError(t, param.Origin_DelegateIssuerToDirector.Set(false))

	assert.Equal(t, "https://origin.example:8443/api/v1.0/issuer/ns/foo", GetNamespaceIssuerURL("/foo"))
	assert.Equal(t, "https://origin.example:8443/api/v1.0/issuer/ns/foo/bar", GetNamespaceIssuerURL("/foo/bar"))
	// Empty namespace yields the bare external URL (legacy IssuerURL() behavior).
	assert.Equal(t, "https://origin.example:8443", GetNamespaceIssuerURL(""))
	// (The delegation-on path resolves the federation director endpoint and is
	// covered by the WS4 e2e once the broker/token harness is available; it is
	// off by default and falls back to the local issuer when no director is known.)
}
