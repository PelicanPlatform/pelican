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

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"golang.org/x/mod/semver"
)

// TestCSharedRoundTrip drives the C-ABI surface the way an external consumer
// (e.g. the XRootD purge plugin) would: configure context, create a lot, then
// query it back — exercising JSON in/out, the string-list allocator, and the
// usage path through the real C entry points (via the Go-typed bridge).
func TestCSharedRoundTrip(t *testing.T) {
	resetStateForTest()
	// Close the manager's DB handle when the test ends. defer runs before
	// t.TempDir's (t.Cleanup-registered) removal, so the SQLite file is unlocked
	// before RemoveAll -- required on Windows, where an open handle blocks it.
	defer resetStateForTest()

	setContextStrGo("lot_home", t.TempDir())
	setContextStrGo("caller", "https://fed.example")

	// A self-parented, non-expiring root lot (the all-zero timestamp sentinel)
	// needs no parent attributions.
	rootJSON := `{"lot_name":"root","owner":"https://fed.example","parents":["root"],` +
		`"paths":[{"path":"/","recursive":false}],` +
		`"management_policy_attrs":{"dedicated_GB":100,"opportunistic_GB":-1,"max_num_objects":-1,` +
		`"creation_time":0,"expiration_time":0,"deletion_time":0}}`
	if err := addLotGo(rootJSON); err != nil {
		t.Fatalf("add_lot: %v", err)
	}

	if rc, err := lotExistsGo("root"); err != nil || rc != 1 {
		t.Fatalf("lot_exists(root) = %d, err=%v; want 1, nil", rc, err)
	}
	if rc, err := isRootGo("root"); err != nil || rc != 1 {
		t.Fatalf("is_root(root) = %d, err=%v; want 1, nil", rc, err)
	}

	lots, err := listAllLotsGo()
	if err != nil {
		t.Fatalf("list_all_lots: %v", err)
	}
	if len(lots) != 1 || lots[0] != "root" {
		t.Fatalf("list_all_lots = %v, want [root]", lots)
	}

	js, err := getLotAsJSONGo("root", false)
	if err != nil {
		t.Fatalf("get_lot_as_json: %v", err)
	}
	var decoded struct {
		LotName string `json:"lot_name"`
		Owner   string `json:"owner"`
	}
	if err := json.Unmarshal([]byte(js), &decoded); err != nil {
		t.Fatalf("get_lot_as_json returned invalid JSON %q: %v", js, err)
	}
	if decoded.LotName != "root" || decoded.Owner != "https://fed.example" {
		t.Fatalf("get_lot_as_json = %+v, want root / https://fed.example", decoded)
	}

	if err := updateLotUsageGo(`{"lot_name":"root","self_GB":5,"self_objects":3}`, false); err != nil {
		t.Fatalf("update_lot_usage: %v", err)
	}
	usage, err := getLotUsageGo(`{"lot_name":"root"}`)
	if err != nil {
		t.Fatalf("get_lot_usage: %v", err)
	}
	if !strings.Contains(usage, `"total_GB"`) {
		t.Fatalf("get_lot_usage missing total_GB: %s", usage)
	}

	if versionGo() == "" {
		t.Fatal("lotman_version returned empty string")
	}
}

// TestVersionIsSemver pins the format of lotman_version()'s return. The original
// library published "v" + major.minor.patch and consumers version-gate on it
// with a semver comparison -- Pelican's own historical gate called
// semver.IsValid, which rejects an unprefixed "0.1.0" and would have refused to
// initialise lot management at all.
func TestVersionIsSemver(t *testing.T) {
	v := versionGo()
	if !strings.HasPrefix(v, "v") {
		t.Errorf("lotman_version() = %q, want the leading %q the original library published", v, "v")
	}
	if !semver.IsValid(v) {
		t.Errorf("lotman_version() = %q, which semver.IsValid rejects", v)
	}
}

// TestCSharedRequiresLotHome verifies operations fail cleanly with an error
// message (not a crash) when lot_home has not been configured.
func TestCSharedRequiresLotHome(t *testing.T) {
	resetStateForTest()

	rc, err := lotExistsGo("root")
	if rc >= 0 || err == nil {
		t.Fatalf("expected an error without lot_home, got rc=%d err=%v", rc, err)
	}
}

// TestRemoveLotRejectsUnimplementedFlags covers the reassignment flags this
// implementation cannot honour. The core reparents every child onto the removed
// lot's parents and never copies the removed lot's policy down; the other
// combinations the C ABI can express mean materially different things. An
// operator retiring an intermediate lot with orphans=false expects that lot's
// children to fall back to `default`, which has no quota, so their data becomes
// reclaimable — accepting the call and reparenting them with their original
// quota intact, then returning success, is the worst outcome available.
func TestRemoveLotRejectsUnimplementedFlags(t *testing.T) {
	resetStateForTest()
	defer resetStateForTest()

	setContextStrGo("lot_home", t.TempDir())
	setContextStrGo("caller", "https://fed.example")

	rootJSON := `{"lot_name":"root","owner":"https://fed.example","parents":["root"],` +
		`"paths":[{"path":"/","recursive":false}],` +
		`"management_policy_attrs":{"dedicated_GB":100,"opportunistic_GB":-1,"max_num_objects":-1,` +
		`"creation_time":0,"expiration_time":0,"deletion_time":0}}`
	if err := addLotGo(rootJSON); err != nil {
		t.Fatalf("add_lot root: %v", err)
	}
	childJSON := `{"lot_name":"child","owner":"https://fed.example","parents":["root"],` +
		`"paths":[{"path":"/child","recursive":true}],` +
		`"management_policy_attrs":{"dedicated_GB":10,"opportunistic_GB":-1,"max_num_objects":-1,` +
		`"creation_time":0,"expiration_time":0,"deletion_time":0}}`
	if err := addLotGo(childJSON); err != nil {
		t.Fatalf("add_lot child: %v", err)
	}

	for _, c := range []struct {
		name                                            string
		orphans, nonOrphans, policyToChildren, override bool
		wantErr                                         string
	}{
		{"orphans to default", false, true, false, false, "orphans"},
		{"non-orphans detached", true, false, false, false, "orphans"},
		{"policy copied to children", true, true, true, false, "assign_policy_to_children"},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := removeLotGo("child", c.orphans, c.nonOrphans, c.policyToChildren, c.override)
			if err == nil {
				t.Fatal("expected an error rather than a silent divergence from the requested behaviour")
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("error %q does not name the unsupported flag (%q)", err, c.wantErr)
			}
			if exists, _ := lotExistsGo("child"); exists != 1 {
				t.Error("the lot must be left alone when the request is refused")
			}
		})
	}

	// The combination the core does implement still works, and override_policy
	// is accepted and ignored, as upstream documents it unimplemented.
	if err := removeLotGo("child", true, true, false, true); err != nil {
		t.Fatalf("supported flag combination was rejected: %v", err)
	}
	if exists, _ := lotExistsGo("child"); exists != 0 {
		t.Error("lot should have been removed")
	}
}
