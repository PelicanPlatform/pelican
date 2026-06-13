//go:build linux && !ppc64le

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

import "testing"

func TestGBBytesConversion(t *testing.T) {
	cases := []struct {
		gb    float64
		bytes int64
	}{
		{0, 0},
		{1, 1_000_000_000},
		{1.11, 1_110_000_000},
		{0.5, 500_000_000},
		{500, 500_000_000_000},
		{-1, -1}, // unbounded sentinel must NOT become -1e9
	}
	for _, c := range cases {
		if got := gbToBytes(c.gb); got != c.bytes {
			t.Errorf("gbToBytes(%v) = %d, want %d", c.gb, got, c.bytes)
		}
		if got := bytesToGB(c.bytes); got != c.gb {
			t.Errorf("bytesToGB(%d) = %v, want %v", c.bytes, got, c.gb)
		}
	}
}

func TestGBBytesPointers(t *testing.T) {
	if got := gbPtrToBytes(nil); got != 0 {
		t.Errorf("gbPtrToBytes(nil) = %d, want 0", got)
	}
	gb := 2.0
	if got := gbPtrToBytes(&gb); got != 2_000_000_000 {
		t.Errorf("gbPtrToBytes(2) = %d, want 2e9", got)
	}
	unb := -1.0
	if got := gbPtrToBytes(&unb); got != -1 {
		t.Errorf("gbPtrToBytes(-1) = %d, want -1 (unbounded)", got)
	}
	if p := bytesToGBPtr(-1); p == nil || *p != -1 {
		t.Errorf("bytesToGBPtr(-1) = %v, want -1", p)
	}
}

func TestInt64PtrValue(t *testing.T) {
	if got := int64PtrValue(nil, -1); got != -1 {
		t.Errorf("int64PtrValue(nil, -1) = %d, want -1", got)
	}
	v := &Int64FromFloat{Value: 42}
	if got := int64PtrValue(v, -1); got != 42 {
		t.Errorf("int64PtrValue(42, -1) = %d, want 42", got)
	}
}
