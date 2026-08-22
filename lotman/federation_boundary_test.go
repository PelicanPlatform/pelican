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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withFederationPrefix installs a federation prefix for the duration of a test,
// standing in for what the V2 launcher sets at startup.
func withFederationPrefix(t *testing.T, prefix string) {
	t.Helper()
	fedPrefixMu.Lock()
	prev := fedPrefix
	fedPrefix = prefix
	fedPrefixMu.Unlock()
	t.Cleanup(func() {
		fedPrefixMu.Lock()
		fedPrefix = prev
		fedPrefixMu.Unlock()
	})
}

// TestLotPathBoundaryRoundTrip pins the operator-facing path boundary. Lots are
// stored federation-qualified so two federations' copies of a namespace resolve
// to different lots, but operators, the REST API, the CLI and the Director all
// speak the bare path. Anything entering the store is qualified and anything
// leaving is stripped, so a create-then-read round trip is the identity.
func TestLotPathBoundaryRoundTrip(t *testing.T) {
	withFederationPrefix(t, "/osg-htc.org:8443")

	cases := []struct {
		bare, stored string
	}{
		{"/atlas", "/osg-htc.org:8443/atlas"},
		{"/atlas/prod/raw", "/osg-htc.org:8443/atlas/prod/raw"},
		{"/", "/osg-htc.org:8443"},
	}
	for _, c := range cases {
		t.Run(c.bare, func(t *testing.T) {
			got := qualifyLotPath(c.bare)
			assert.Equal(t, c.stored, got, "qualify")
			assert.Equal(t, c.bare, unqualifyLotPath(got), "round trip must be the identity")
		})
	}
}

// TestQualifyLotPathIsIdempotent guards the failure mode where a caller has
// already qualified a path: the prefix must never be applied twice. InitLotman
// and LaunchRenewalRoutine both qualify the ads they are handed, so a third
// caller doing the same is a live possibility.
func TestQualifyLotPathIsIdempotent(t *testing.T) {
	withFederationPrefix(t, "/osg-htc.org:8443")

	once := qualifyLotPath("/atlas")
	twice := qualifyLotPath(once)
	require.Equal(t, once, twice, "qualifying an already-qualified path must not double-prefix")
}

// TestUnqualifyLotPathRequiresSegmentBoundary makes sure the prefix check does
// not match a namespace that merely starts with the same characters.
func TestUnqualifyLotPathRequiresSegmentBoundary(t *testing.T) {
	withFederationPrefix(t, "/osg-htc.org")

	// "/osg-htc.orgy" is a different federation, not "/y" under this one.
	require.Equal(t, "/osg-htc.orgy/atlas", unqualifyLotPath("/osg-htc.orgy/atlas"))
	require.Equal(t, "/atlas", unqualifyLotPath("/osg-htc.org/atlas"))
}

// TestLotPathBoundaryIsNoOpWithoutPrefix covers the V1 (XRootD) deployment,
// where no prefix is configured and paths are stored bare.
func TestLotPathBoundaryIsNoOpWithoutPrefix(t *testing.T) {
	withFederationPrefix(t, "")

	require.Equal(t, "/atlas", qualifyLotPath("/atlas"))
	require.Equal(t, "/atlas", unqualifyLotPath("/atlas"))
}

// TestNormaliseLotPathCleans covers the planner's path normalisation agreeing
// with what the core stores. Without cleaning, "/x", "/./x" and "/x/y/.." are
// three paths to the planner's dedup and fair-share arithmetic but one path once
// stored -- which would let an origin claim several quota shares for one prefix.
func TestNormaliseLotPathCleans(t *testing.T) {
	cases := map[string]string{
		"/atlas":        "/atlas",
		"/atlas/":       "/atlas",
		"/./atlas":      "/atlas",
		"/atlas/cms/..": "/atlas",
		"//atlas//x//":  "/atlas/x",
		"/":             "/",
	}
	for in, want := range cases {
		if got := normaliseLotPath(in); got != want {
			t.Errorf("normaliseLotPath(%q) = %q, want %q", in, got, want)
		}
	}
}
