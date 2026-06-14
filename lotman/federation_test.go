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

package lotman

import (
	"testing"

	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

func TestFederationQualifyAds(t *testing.T) {
	t.Cleanup(func() { SetFederationPrefix("") })

	ads := []server_structs.NamespaceAdV2{{Path: "/atlas"}, {Path: "/cms/x"}}

	// V1 (no prefix): paths stay bare so xrootd is not confused.
	SetFederationPrefix("")
	out := federationQualifyAds(ads)
	if out[0].Path != "/atlas" || out[1].Path != "/cms/x" {
		t.Errorf("V1 paths should be unchanged, got %q, %q", out[0].Path, out[1].Path)
	}

	// V2 (prefix set): paths are federation-qualified.
	SetFederationPrefix("/osg-htc.org")
	out = federationQualifyAds(ads)
	if out[0].Path != "/osg-htc.org/atlas" || out[1].Path != "/osg-htc.org/cms/x" {
		t.Errorf("V2 paths should be fed-qualified, got %q, %q", out[0].Path, out[1].Path)
	}
	// The input slice must not be mutated.
	if ads[0].Path != "/atlas" {
		t.Errorf("input ads should not be mutated, got %q", ads[0].Path)
	}
}

func TestMonitoringBasePath(t *testing.T) {
	t.Cleanup(func() { SetFederationPrefix("") })

	SetFederationPrefix("")
	if got := monitoringBasePath(); got != normaliseLotPath(server_utils.MonitoringBaseNs) {
		t.Errorf("V1 monitoring base = %q, want %q", got, server_utils.MonitoringBaseNs)
	}

	SetFederationPrefix("/osg-htc.org")
	want := normaliseLotPath("/osg-htc.org" + server_utils.MonitoringBaseNs)
	if got := monitoringBasePath(); got != want {
		t.Errorf("V2 monitoring base = %q, want %q", got, want)
	}
}
