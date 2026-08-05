package local_cache

import (
	"math"
	"testing"
)

// TestScaleByRatioNoOverflow pins the arithmetic behind ForcePurgeToBytes's
// per-directory targets. The natural `value * num / denom` wraps once the
// product exceeds 2^64 -- roughly 4 GB x 4 GB, i.e. any real cache -- and the
// wrapped value is still a plausible byte count, so an admin asking to free 10%
// could silently get a target near zero and lose the whole directory.
func TestScaleByRatioNoOverflow(t *testing.T) {
	const tb = uint64(1) << 40
	cases := []struct {
		name              string
		value, num, denom uint64
		want              uint64
	}{
		{"single 10TB dir, purge to 90%", 9 * tb, 10 * tb, 10 * tb, 9 * tb},
		{"two equal dirs", 9 * tb, 10 * tb, 20 * tb, 45 * tb / 10},
		{"uneven split", 100 * tb, 3 * tb, 7 * tb, 47121926904685},
		{"exact division", 1000, 50, 10, 5000},
		{"zero denominator", 5, 5, 0, 0},
		{"saturates rather than wraps", math.MaxUint64, math.MaxUint64, 1, math.MaxUint64},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scaleByRatio(c.value, c.num, c.denom)
			if got != c.want {
				t.Errorf("scaleByRatio(%d, %d, %d) = %d, want %d", c.value, c.num, c.denom, got, c.want)
			}
			// The naive form is what this function exists to avoid.
			if c.denom != 0 {
				if naive := (c.value * c.num) / c.denom; naive != got {
					t.Logf("naive arithmetic would have produced %d (off by %d)", naive, int64(naive)-int64(got))
				}
			}
		})
	}
}
