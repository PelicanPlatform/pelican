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
)

// TestCSharedRoundTrip drives the C-ABI surface the way an external consumer
// (e.g. the XRootD purge plugin) would: configure context, create a lot, then
// query it back — exercising JSON in/out, the string-list allocator, and the
// usage path through the real C entry points (via the Go-typed bridge).
func TestCSharedRoundTrip(t *testing.T) {
	resetStateForTest()

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

// TestCSharedRequiresLotHome verifies operations fail cleanly with an error
// message (not a crash) when lot_home has not been configured.
func TestCSharedRequiresLotHome(t *testing.T) {
	resetStateForTest()

	rc, err := lotExistsGo("root")
	if rc >= 0 || err == nil {
		t.Fatalf("expected an error without lot_home, got rc=%d err=%v", rc, err)
	}
}
