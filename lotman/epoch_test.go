//go:build linux && !ppc64le && lotman

package lotman

import (
	"reflect"
	"testing"
)

// TestTopLevelSiblingsExcludesSyntheticRoot guards against a regression in
// which the synthetic "/" root lot (the parent-pool entry that lives in
// `effective` alongside real namespace paths) was treated as a strict
// ancestor of every real namespace by the inner ancestor-check loop. The
// outer loop skipped "/" but the inner loop did not, so for any real path
// `c`, the candidate `d == "/"` would satisfy pathContains("/", c) and
// mark c as non-top-level, returning an empty sibling list. That broke
// the per-instant fair-share divisor in computeMinOverEpochsShare and
// caused renewal successors to be stamped with the full root capacity,
// which lotman then rejected as a hierarchy violation at admission.
func TestTopLevelSiblingsExcludesSyntheticRoot(t *testing.T) {
	effective := map[string][]Lot{
		"/":           nil, // synthetic root lot
		"/my-prefix":  nil,
		"/my-prefix2": nil,
	}

	got := topLevelSiblings("/my-prefix", effective)
	want := []string{"/my-prefix2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("topLevelSiblings(/my-prefix) = %v, want %v", got, want)
	}

	got = topLevelSiblings("/my-prefix2", effective)
	want = []string{"/my-prefix"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("topLevelSiblings(/my-prefix2) = %v, want %v", got, want)
	}
}

// TestTopLevelSiblingsRespectsTrueAncestors confirms that a real
// ancestor path in `effective` still hides its descendants from the
// top-level sibling set.
func TestTopLevelSiblingsRespectsTrueAncestors(t *testing.T) {
	effective := map[string][]Lot{
		"/":            nil,
		"/foo":         nil,
		"/foo/bar":     nil, // child of /foo, not top-level
		"/baz":         nil,
	}
	got := topLevelSiblings("/foo", effective)
	want := []string{"/baz"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("topLevelSiblings(/foo) = %v, want %v", got, want)
	}
}
