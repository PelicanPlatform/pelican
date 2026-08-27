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

package origin_serve

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseObjectMetadataHeader_Empty(t *testing.T) {
	got, err := ParseObjectMetadataHeader("")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty map, got %#v", got)
	}
}

func TestParseObjectMetadataHeader_Primitives(t *testing.T) {
	hdr := `experiment="atlas", run_number=4172, weight=3.14, is_test=?0, code=cms`
	got, err := ParseObjectMetadataHeader(hdr)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	want := map[string]any{
		"experiment": "atlas",
		"run_number": int64(4172),
		"weight":     3.14,
		"is_test":    false,
		"code":       "cms",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestParseObjectMetadataHeader_ByteSequence(t *testing.T) {
	// "hello" base64 = aGVsbG8=
	hdr := `payload=:aGVsbG8=:`
	got, err := ParseObjectMetadataHeader(hdr)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	v, ok := got["payload"].(string)
	if !ok {
		t.Fatalf("payload type %T", got["payload"])
	}
	if !strings.HasPrefix(v, ":") || !strings.HasSuffix(v, ":") {
		t.Fatalf("payload = %q; want :base64:", v)
	}
}

func TestParseObjectMetadataHeader_RejectsReservedKeys(t *testing.T) {
	hdr := `experiment="atlas", path="/exfil", size=99`
	got, err := ParseObjectMetadataHeader(hdr)
	if err == nil {
		t.Fatal("expected non-fatal error indicating reserved keys were dropped")
	}
	if got["experiment"] != "atlas" {
		t.Fatalf("non-reserved key dropped: %#v", got)
	}
	if _, present := got["path"]; present {
		t.Fatal("reserved key 'path' should be absent")
	}
	if _, present := got["size"]; present {
		t.Fatal("reserved key 'size' should be absent")
	}
}

func TestParseObjectMetadataHeader_Malformed(t *testing.T) {
	if _, err := ParseObjectMetadataHeader("definitely not = a struct field"); err == nil {
		t.Fatal("expected error from malformed input")
	}
}

func TestParseObjectMetadataHeader_InnerListRejected(t *testing.T) {
	if _, err := ParseObjectMetadataHeader(`runs=(1 2 3)`); err == nil {
		t.Fatal("expected v1 to reject inner-list values")
	}
}

// TestParseObjectMetadataHeader_RoundTripFromClient confirms that
// the SFV string the *client* emits (via the client package's
// internal buildObjectMetadataHeader) is exactly what the origin-
// side parser accepts. This is the wire contract; we test it
// directly by hand-coding the format the client produces today and
// ensuring both ends agree.
func TestParseObjectMetadataHeader_RoundTripFromClient(t *testing.T) {
	// This is the deterministic output of
	// client.buildObjectMetadataHeader for the given inputs (covered
	// by client/object_metadata_test.go::TestBuildObjectMetadataHeader_RoundTrip).
	hdr := `experiment="atlas", is_test=?0, run_number=4172, weight=3.14`
	got, err := ParseObjectMetadataHeader(hdr)
	if err != nil {
		t.Fatalf("origin parser rejected client output: %v", err)
	}
	if got["experiment"] != "atlas" {
		t.Fatalf("experiment = %v", got["experiment"])
	}
	if v, ok := got["run_number"].(int64); !ok || v != 4172 {
		t.Fatalf("run_number = %#v", got["run_number"])
	}
	if v, ok := got["weight"].(float64); !ok || v != 3.14 {
		t.Fatalf("weight = %#v", got["weight"])
	}
	if v, ok := got["is_test"].(bool); !ok || v {
		t.Fatalf("is_test = %#v", got["is_test"])
	}
}
