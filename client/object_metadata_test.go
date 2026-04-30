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

package client

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseObjectMetadataJSON_Primitives(t *testing.T) {
	got, err := ParseObjectMetadataJSON([]byte(`{
		"experiment": "atlas",
		"run_number": 4172,
		"weight": 3.14,
		"is_test": false
	}`))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got["experiment"] != "atlas" {
		t.Errorf("experiment = %v", got["experiment"])
	}
	if v, ok := got["run_number"].(int64); !ok || v != 4172 {
		t.Errorf("run_number = %#v (want int64 4172)", got["run_number"])
	}
	if v, ok := got["weight"].(float64); !ok || v != 3.14 {
		t.Errorf("weight = %#v (want float64 3.14)", got["weight"])
	}
	if v, ok := got["is_test"].(bool); !ok || v {
		t.Errorf("is_test = %#v (want false)", got["is_test"])
	}
}

func TestParseObjectMetadataJSON_RejectsReservedKeys(t *testing.T) {
	for _, k := range ReservedObjectMetadataKeys {
		body := []byte(`{"` + k + `": "x"}`)
		if _, err := ParseObjectMetadataJSON(body); err == nil {
			t.Fatalf("reserved key %q should have been rejected", k)
		}
	}
}

func TestParseObjectMetadataJSON_RejectsNested(t *testing.T) {
	cases := []string{
		`{"x": {"nested": 1}}`,
		`{"x": [1, 2, 3]}`,
		`{"x": null}`,
	}
	for _, c := range cases {
		if _, err := ParseObjectMetadataJSON([]byte(c)); err == nil {
			t.Fatalf("expected rejection of %q", c)
		}
	}
}

func TestParseObjectMetadataJSON_RejectsTopLevelNonObject(t *testing.T) {
	for _, c := range []string{`["a", "b"]`, `"just a string"`, `42`} {
		if _, err := ParseObjectMetadataJSON([]byte(c)); err == nil {
			t.Fatalf("expected rejection of top-level %q", c)
		}
	}
}

func TestParseObjectMetadataJSON_Malformed(t *testing.T) {
	if _, err := ParseObjectMetadataJSON([]byte(`{not valid`)); err == nil {
		t.Fatal("expected JSON parse error")
	}
}

func TestBuildObjectMetadataHeader_RoundTrip(t *testing.T) {
	got, err := BuildObjectMetadataHeader(map[string]any{
		"experiment": "atlas",
		"run_number": int64(4172),
		"weight":     3.14,
		"is_test":    false,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	// Deterministic order makes the assertion stable. (sortStrings
	// in the impl is alphabetical.)
	want := `experiment="atlas", is_test=?0, run_number=4172, weight=3.14`
	if got != want {
		t.Fatalf("header = %q\n want %q", got, want)
	}
}

func TestBuildObjectMetadataHeader_EmptyMap(t *testing.T) {
	got, err := BuildObjectMetadataHeader(nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "" {
		t.Fatalf("header = %q; want empty", got)
	}
}

func TestBuildObjectMetadataHeader_AcceptsIntAndFloat(t *testing.T) {
	got, err := BuildObjectMetadataHeader(map[string]any{
		"a": int(7),
		"b": int64(99),
		"c": float64(0.5),
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !strings.Contains(got, "a=7") || !strings.Contains(got, "b=99") || !strings.Contains(got, "c=0.5") {
		t.Fatalf("header = %q", got)
	}
}

func TestLoadObjectMetadataFile_HappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "meta.json")
	if err := os.WriteFile(path, []byte(`{"experiment":"atlas","run":4172}`), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := LoadObjectMetadataFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got["experiment"] != "atlas" {
		t.Fatalf("got %#v", got)
	}
}

func TestLoadObjectMetadataFile_MissingFile(t *testing.T) {
	if _, err := LoadObjectMetadataFile("/no/such/file.json"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadObjectMetadataFile_EmptyPath(t *testing.T) {
	if _, err := LoadObjectMetadataFile(""); err == nil {
		t.Fatal("expected error for empty path")
	}
}
