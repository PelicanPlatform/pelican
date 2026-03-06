// Property-based tests for the HA director design.
//
// These tests verify the invariants that the design relies on:
//
//  1. Ad ordering (After) is a strict partial order: anti-symmetric and transitive.
//     This underlies the coalescing logic that keeps only the newest pending ad.
//
//  2. Server restarts (new StartTime) unconditionally win over any prior generation,
//     ensuring a restarted server never gets stuck behind stale ads.
//
//  3. forwardServiceAd sends to exactly the directors not in seenBy (minus self).
//     This is the core invariant of the flood-forward anti-loop mechanism.
//
//  4. The seenBy list grows by exactly the current director on each hop.
//     This ensures the exclusion set always reflects the real forwarding history.
//
//  5. Time-skew correction preserves the intended ad lifetime.
//     This ensures expiry times remain meaningful across clock-skewed directors.

package director

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"slices"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

// makeOrderingAd constructs a minimal ServerBaseAd with only the fields that
// After() uses for comparison. All other fields are left at zero values.
func makeOrderingAd(name string, startTime int64, instanceID string, genID uint64) server_structs.ServerBaseAd {
	return server_structs.ServerBaseAd{
		Name:         name,
		StartTime:    startTime,
		InstanceID:   instanceID,
		GenerationID: genID,
	}
}

// TestAfterOrderingIsAntiSymmetric verifies that the After ordering never
// declares two ads mutually "after" each other. Specifically: if A.After(B)
// returns AdAfterTrue, then B.After(A) must return AdAfterFalse.
//
// This property is required for the coalescing logic: if both "new beats old"
// and "old beats new" could be true simultaneously, the buffer would make
// non-deterministic replacement decisions.
func TestAfterOrderingIsAntiSymmetric(t *testing.T) {
	const name = "server-1"
	rng := rand.New(rand.NewSource(42))

	for trial := range 2000 {
		startA := rng.Int63n(10) + 1
		startB := rng.Int63n(10) + 1
		instA := fmt.Sprintf("inst-%d", rng.Intn(4)+1)
		instB := fmt.Sprintf("inst-%d", rng.Intn(4)+1)
		genA := uint64(rng.Intn(10) + 1)
		genB := uint64(rng.Intn(10) + 1)

		adA := makeOrderingAd(name, startA, instA, genA)
		adB := makeOrderingAd(name, startB, instB, genB)

		afterAB := adA.After(&adB)
		afterBA := adB.After(&adA)

		// Mutual "after" is impossible: if A > B then B must not be > A.
		assert.False(t,
			afterAB == server_structs.AdAfterTrue && afterBA == server_structs.AdAfterTrue,
			"trial %d: A and B cannot both be after each other: A=%+v B=%+v", trial, adA, adB,
		)
		// Strict direction: AdAfterTrue implies the reverse is AdAfterFalse.
		if afterAB == server_structs.AdAfterTrue {
			assert.Equal(t, server_structs.AdAfterFalse, afterBA,
				"trial %d: A>B implies B must not be after A: A=%+v B=%+v", trial, adA, adB)
		}
		if afterBA == server_structs.AdAfterTrue {
			assert.Equal(t, server_structs.AdAfterFalse, afterAB,
				"trial %d: B>A implies A must not be after B: A=%+v B=%+v", trial, adA, adB)
		}
	}
}

// TestAfterOrderingIsTransitive verifies that the After ordering is transitive:
// if A > B and B > C, then A > C. This is required for the coalescing buffer
// to have a consistent "most recent" notion across a sequence of arrivals.
//
// Two sub-cases are exercised:
//  1. Same instance, GenerationID ordering — the steady-state case.
//  2. Different start times — the server-restart case.
func TestAfterOrderingIsTransitive(t *testing.T) {
	const name = "server-1"
	rng := rand.New(rand.NewSource(99))

	t.Run("same_instance_genID_order", func(t *testing.T) {
		for trial := range 1000 {
			gens := [3]uint64{
				uint64(rng.Intn(1000) + 1),
				uint64(rng.Intn(1000) + 1),
				uint64(rng.Intn(1000) + 1),
			}
			sort.Slice(gens[:], func(i, j int) bool { return gens[i] > gens[j] })
			if gens[0] == gens[1] || gens[1] == gens[2] {
				continue // equal generationIDs produce AdAfterFalse in both directions; skip
			}

			adA := makeOrderingAd(name, 100, "inst-1", gens[0])
			adB := makeOrderingAd(name, 100, "inst-1", gens[1])
			adC := makeOrderingAd(name, 100, "inst-1", gens[2])

			require.Equal(t, server_structs.AdAfterTrue, adA.After(&adB), "trial %d: A should be after B", trial)
			require.Equal(t, server_structs.AdAfterTrue, adB.After(&adC), "trial %d: B should be after C", trial)
			assert.Equal(t, server_structs.AdAfterTrue, adA.After(&adC),
				"trial %d: transitivity violated (A>B, B>C => A>C), genIDs=%v", trial, gens)
		}
	})

	t.Run("distinct_start_times", func(t *testing.T) {
		for trial := range 1000 {
			starts := [3]int64{
				rng.Int63n(1000) + 1,
				rng.Int63n(1000) + 1,
				rng.Int63n(1000) + 1,
			}
			sort.Slice(starts[:], func(i, j int) bool { return starts[i] > starts[j] })
			if starts[0] == starts[1] || starts[1] == starts[2] {
				continue
			}

			// Each ad comes from a distinct instance; GenID doesn't matter.
			adA := makeOrderingAd(name, starts[0], "inst-a", 5)
			adB := makeOrderingAd(name, starts[1], "inst-b", 5)
			adC := makeOrderingAd(name, starts[2], "inst-c", 5)

			require.Equal(t, server_structs.AdAfterTrue, adA.After(&adB), "trial %d: A should be after B", trial)
			require.Equal(t, server_structs.AdAfterTrue, adB.After(&adC), "trial %d: B should be after C", trial)
			assert.Equal(t, server_structs.AdAfterTrue, adA.After(&adC),
				"trial %d: transitivity violated (start times), starts=%v", trial, starts)
		}
	})
}

// TestAfterNameMismatchAlwaysUnknown verifies that comparing ads from different
// servers always returns AdAfterUnknown. Ordering between ads of different
// servers is meaningless, so the coalescing logic must not replace an ad from
// server X with one from server Y.
func TestAfterNameMismatchAlwaysUnknown(t *testing.T) {
	rng := rand.New(rand.NewSource(77))

	for trial := range 500 {
		adA := makeOrderingAd("server-A", rng.Int63n(1000)+1, "inst-1", uint64(rng.Intn(100)+1))
		adB := makeOrderingAd("server-B", rng.Int63n(1000)+1, "inst-2", uint64(rng.Intn(100)+1))

		assert.Equal(t, server_structs.AdAfterUnknown, adA.After(&adB),
			"trial %d: mismatched names must return Unknown", trial)
		assert.Equal(t, server_structs.AdAfterUnknown, adB.After(&adA),
			"trial %d: mismatched names must return Unknown (reversed)", trial)
	}
}

// TestAfterServerRestartAlwaysWins verifies the restart-ordering property:
// an ad from a newly restarted server (higher StartTime) must always compare
// as "after" an ad from the previous incarnation, regardless of GenerationIDs.
//
// This ensures that after a crash-restart the director discards all stale state
// from the old instance and adopts the fresh advertisement.
func TestAfterServerRestartAlwaysWins(t *testing.T) {
	const name = "server-1"
	rng := rand.New(rand.NewSource(11))

	for trial := range 1000 {
		oldStart := rng.Int63n(1000) + 1
		newStart := oldStart + rng.Int63n(1000) + 1 // always strictly later

		// Old instance may have accumulated a very high generation counter;
		// the new instance starts fresh at gen=1.
		oldGen := uint64(rng.Intn(100000) + 1)
		newGen := uint64(1)

		oldAd := makeOrderingAd(name, oldStart, "inst-old", oldGen)
		newAd := makeOrderingAd(name, newStart, "inst-new", newGen)

		assert.Equal(t, server_structs.AdAfterTrue, newAd.After(&oldAd),
			"trial %d: restarted server must be after old instance regardless of genID (oldGen=%d)", trial, oldGen)
		assert.Equal(t, server_structs.AdAfterFalse, oldAd.After(&newAd),
			"trial %d: old instance must not be after restarted server", trial)
	}
}

// TestAfterMissingFieldsReturnUnknown verifies that any missing required field
// (zero StartTime, empty InstanceID, zero GenerationID) causes After() to
// return AdAfterUnknown rather than silently picking a winner.
//
// The coalescing logic treats Unknown as "keep existing", so incomplete ads
// never incorrectly displace a fully-populated ad.
func TestAfterMissingFieldsReturnUnknown(t *testing.T) {
	good := makeOrderingAd("server", 100, "inst-1", 5)

	cases := []struct {
		name string
		bad  server_structs.ServerBaseAd
	}{
		{"zero_start_time", makeOrderingAd("server", 0, "inst-1", 5)},
		{"empty_instance_id", makeOrderingAd("server", 100, "", 5)},
		{"zero_generation_id", makeOrderingAd("server", 100, "inst-1", 0)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, server_structs.AdAfterUnknown, good.After(&tc.bad),
				"good.After(incomplete) should be Unknown")
			assert.Equal(t, server_structs.AdAfterUnknown, tc.bad.After(&good),
				"incomplete.After(good) should be Unknown")
		})
	}
}

// setupForwardingState resets all package-level singletons used by the
// forwarding machinery so that tests can control the "current director" name.
//
// The directorNameOnce is locked with a no-op so that getMyName() returns
// directorName directly without consulting server_utils.GetServerMetadata.
func setupForwardingState(t *testing.T) {
	t.Helper()
	directorNameOnce = sync.Once{}
	directorName = ""
	directorNameError = nil
	directorNameOnce.Do(func() {}) // lock the once; getMyName() will return directorName directly
	t.Cleanup(func() {
		directorNameOnce = sync.Once{}
		directorName = ""
		directorNameError = nil
	})
}

// makeTestDirector registers a directorInfo in the global cache and returns
// the channel on which it would receive forwarded ads.
func makeTestDirector(t *testing.T, name string, ttl time.Duration) chan *forwardAdInfo {
	t.Helper()
	ch := make(chan *forwardAdInfo, 20)
	info := &directorInfo{
		ad: &server_structs.DirectorAd{
			AdvertiseUrl: "http://" + name + ".example.com",
			ServerBaseAd: server_structs.ServerBaseAd{
				Name:         name,
				InstanceID:   "inst-" + name,
				StartTime:    12345,
				GenerationID: 1,
				Version:      "v1",
			},
		},
		forwardAdChan: ch,
	}
	directorAds.Set(name, info, ttl)
	return ch
}

// makeTestServiceAd builds a minimal OriginAdvertiseV2 for use in forwarding tests.
func makeTestServiceAd() *server_structs.OriginAdvertiseV2 {
	return &server_structs.OriginAdvertiseV2{
		ServerBaseAd: server_structs.ServerBaseAd{
			Name:         "origin-1",
			InstanceID:   "origin-inst",
			StartTime:    12345,
			GenerationID: 1,
			Version:      "v1",
			Expiration:   time.Unix(99999, 0).UTC(),
		},
	}
}

// TestSeenByExclusionIsExact is the core property of the HA anti-loop design:
// forwardServiceAd must send to *exactly* the directors that are not in the
// effective seenBy set (seenBy ∪ {self}).
//
// Under-sending (missing a live director) means some directors never learn
// about an origin. Over-sending (forwarding to a seenBy director) would
// create forwarding loops in multi-director topologies.
//
// The test exercises 100 random configurations: varying numbers of directors
// (2–8) and varying sizes of the initial seenBy set.
func TestSeenByExclusionIsExact(t *testing.T) {
	require.NoError(t, param.Set(param.Server_ExternalWebUrl.GetName(), "http://test-self.example.com"))
	t.Cleanup(func() { _ = param.Set(param.Server_ExternalWebUrl.GetName(), "") })

	setupForwardingState(t)

	rng := rand.New(rand.NewSource(42))

	for trial := range 100 {
		directorAds.DeleteAll()

		n := rng.Intn(7) + 2 // 2–8 directors
		names := make([]string, n)
		for i := range names {
			names[i] = fmt.Sprintf("dir%d-t%d", i+1, trial)
		}

		// names[0] is the "current" director (self).
		selfName := names[0]
		directorName = selfName

		// Pick a random subset of the non-self directors for seenBy.
		numSeenBy := rng.Intn(n) // 0 … n-1
		seenBy := make([]string, 0, numSeenBy)
		seenBySet := map[string]bool{selfName: true} // self is always excluded
		perm := rng.Perm(n - 1)
		for _, idx := range perm[:numSeenBy] {
			name := names[idx+1] // skip names[0]
			if !seenBySet[name] {
				seenBy = append(seenBy, name)
				seenBySet[name] = true
			}
		}

		channels := make(map[string]chan *forwardAdInfo, n)
		for _, dirName := range names {
			channels[dirName] = makeTestDirector(t, dirName, 15*time.Minute)
		}

		ctx := context.Background()
		forwardServiceAd(ctx, makeTestServiceAd(), server_structs.OriginType, seenBy)

		for _, dirName := range names {
			ch := channels[dirName]
			shouldReceive := !seenBySet[dirName]
			select {
			case msg := <-ch:
				if !shouldReceive {
					assert.Fail(t,
						"director in seenBy received a forwarded ad",
						"trial=%d director=%s seenBy=%v serverBase=%+v", trial, dirName, seenBy, msg.serverBase,
					)
				}
			default:
				if shouldReceive {
					assert.Fail(t,
						"director not in seenBy did not receive a forwarded ad",
						"trial=%d director=%s seenBy=%v n=%d", trial, dirName, seenBy, n,
					)
				}
			}
		}
	}
}

// TestSeenByGrowsByExactlyOnePerHop verifies the seenBy growth property:
// when director D calls forwardServiceAd with an initial seenBy list, the
// payload delivered to downstream directors must contain exactly
// initialSeenBy ++ [D].
//
// If this invariant breaks—e.g., D forgets to add itself, or adds duplicates—
// the exclusion check in a downstream director becomes incorrect.
func TestSeenByGrowsByExactlyOnePerHop(t *testing.T) {
	require.NoError(t, param.Set(param.Server_ExternalWebUrl.GetName(), "http://test-self.example.com"))
	t.Cleanup(func() { _ = param.Set(param.Server_ExternalWebUrl.GetName(), "") })

	setupForwardingState(t)

	const currentDirector = "hop-director"
	directorName = currentDirector

	rng := rand.New(rand.NewSource(55))

	for trial := range 100 {
		directorAds.DeleteAll()

		// Build a seenBy list of 0–4 arbitrary upstream directors.
		numPrev := rng.Intn(5)
		initialSeenBy := make([]string, numPrev)
		for i := range initialSeenBy {
			initialSeenBy[i] = fmt.Sprintf("upstream-%d-t%d", i+1, trial)
		}

		// Register one downstream director that is not in seenBy.
		const downstream = "downstream-dir"
		ch := makeTestDirector(t, downstream, 15*time.Minute)

		ctx := context.Background()
		forwardServiceAd(ctx, makeTestServiceAd(), server_structs.OriginType, initialSeenBy)

		select {
		case info := <-ch:
			data, err := io.ReadAll(info.contents)
			require.NoError(t, err)
			var fwd forwardAd
			require.NoError(t, json.Unmarshal(data, &fwd))

			// The seenBy in the payload must be exactly initialSeenBy + currentDirector.
			expected := append(slices.Clone(initialSeenBy), currentDirector)
			assert.Equal(t, expected, fwd.SeenBy,
				"trial %d: seenBy must grow by exactly one hop", trial)
		default:
			assert.Fail(t, "downstream director should have received the ad",
				"trial=%d initialSeenBy=%v", trial, initialSeenBy)
		}
	}
}

// TestSeenByNoDuplicates verifies that the seenBy list never contains duplicate
// entries after repeated forwarding. Duplicates would bloat the payload and
// could cause bugs in downstream directors that use seenBy for set membership.
func TestSeenByNoDuplicates(t *testing.T) {
	require.NoError(t, param.Set(param.Server_ExternalWebUrl.GetName(), "http://test-self.example.com"))
	t.Cleanup(func() { _ = param.Set(param.Server_ExternalWebUrl.GetName(), "") })

	setupForwardingState(t)

	rng := rand.New(rand.NewSource(13))

	for trial := range 50 {
		directorAds.DeleteAll()

		n := rng.Intn(6) + 3 // 3–8 directors
		names := make([]string, n)
		for i := range names {
			names[i] = fmt.Sprintf("dir%d-nd%d", i+1, trial)
		}

		directorName = names[0]

		// Start the forwarding with no seenBy (simulates the first hop).
		channels := make(map[string]chan *forwardAdInfo, n)
		for _, name := range names {
			channels[name] = makeTestDirector(t, name, 15*time.Minute)
		}

		ctx := context.Background()
		forwardServiceAd(ctx, makeTestServiceAd(), server_structs.OriginType, nil)

		// Collect all payloads and verify no seenBy list has duplicates.
		for _, name := range names[1:] {
			select {
			case info := <-channels[name]:
				data, err := io.ReadAll(info.contents)
				require.NoError(t, err)
				var fwd forwardAd
				require.NoError(t, json.Unmarshal(data, &fwd))

				seen := make(map[string]int)
				for _, entry := range fwd.SeenBy {
					seen[entry]++
				}
				for entry, count := range seen {
					assert.Equal(t, 1, count,
						"trial %d: seenBy entry %q appears %d times in payload for %s",
						trial, entry, count, name)
				}
			default:
				assert.Fail(t, "director should have received the ad",
					"trial=%d director=%s (only names[0]=%s is excluded)", trial, name, names[0])
			}
		}
	}
}

// TestTimeSkewCorrectionPreservesLifetime verifies the invariant of the time-skew
// correction in CorrectTimeSkew: when a significant clock skew is detected,
// the corrected expiry must equal receivedAt + originalLifetime.
//
// This matters because an ad sent with a 15-minute lifetime should remain valid
// for 15 minutes from the perspective of the *receiving* director, regardless
// of clock differences.
func TestTimeSkewCorrectionPreservesLifetime(t *testing.T) {
	rng := rand.New(rand.NewSource(77))

	const tolerance = 5 * time.Millisecond

	for trial := range 1000 {
		// Random ad lifetime: 1–30 minutes.
		lifetime := time.Duration(rng.Intn(29*60)+60) * time.Second

		// Random skew well above the 100ms threshold.
		skew := time.Duration(rng.Intn(10000)+200) * time.Millisecond

		sentAt := time.Now()
		sentExpiry := sentAt.Add(lifetime)
		receivedAt := sentAt.Add(skew)

		// Call the actual CorrectTimeSkew function from the codebase.
		correctedExpiry := CorrectTimeSkew(sentAt, sentExpiry, receivedAt)

		// Property: corrected expiry ≈ receivedAt + originalLifetime.
		expectedExpiry := receivedAt.Add(lifetime)
		diff := correctedExpiry.Sub(expectedExpiry)
		if diff < 0 {
			diff = -diff
		}
		assert.LessOrEqual(t, diff, tolerance,
			"trial %d: skew correction failed to preserve lifetime (lifetime=%v skew=%v)", trial, lifetime, skew)
	}
}

// TestTimeSkewCorrectionBelowThresholdIsNoop verifies that small clock
// differences (≤100ms) do not trigger any correction. The ad's expiry should
// remain exactly as the sender set it.
func TestTimeSkewCorrectionBelowThresholdIsNoop(t *testing.T) {
	rng := rand.New(rand.NewSource(88))

	for trial := range 500 {
		lifetime := time.Duration(rng.Intn(29*60)+60) * time.Second
		// Skew is at or below the 100ms threshold (could be negative too).
		skewMs := rng.Int63n(201) - 100 // −100ms … +100ms
		skew := time.Duration(skewMs) * time.Millisecond

		sentAt := time.Now()
		originalExpiry := sentAt.Add(lifetime)
		receivedAt := sentAt.Add(skew)

		// Call the actual CorrectTimeSkew function from the codebase.
		correctedExpiry := CorrectTimeSkew(sentAt, originalExpiry, receivedAt)

		assert.Equal(t, originalExpiry, correctedExpiry,
			"trial %d: skew (%v) is within threshold; expiry must not be modified", trial, skew)
	}
}

// TestForwardingReachesAllDirectors verifies the coverage guarantee:
// for any topology of N directors, every director (except the origin) must
// eventually receive the service ad after the flood-forward process runs to
// completion. This is tested for 2–8 directors.
//
// The test simulates the full forwarding chain: each received message is
// re-processed as if the receiving director were the current one, using the
// seenBy from the payload.
func TestForwardingReachesAllDirectors(t *testing.T) {
	require.NoError(t, param.Set(param.Server_ExternalWebUrl.GetName(), "http://test-self.example.com"))
	t.Cleanup(func() { _ = param.Set(param.Server_ExternalWebUrl.GetName(), "") })

	for n := 2; n <= 8; n++ {
		t.Run(fmt.Sprintf("directors=%d", n), func(t *testing.T) {
			setupForwardingState(t)
			directorAds.DeleteAll()

			names := make([]string, n)
			for i := range names {
				names[i] = fmt.Sprintf("dir%d", i+1)
			}

			channels := make(map[string]chan *forwardAdInfo, n)
			for _, name := range names {
				ch := make(chan *forwardAdInfo, 1000)
				channels[name] = ch
				info := &directorInfo{
					ad: &server_structs.DirectorAd{
						AdvertiseUrl: "http://" + name + ".example.com",
						ServerBaseAd: server_structs.ServerBaseAd{
							Name:         name,
							InstanceID:   "inst-" + name,
							StartTime:    12345,
							GenerationID: 1,
							Version:      "v1",
						},
					},
					forwardAdChan: ch,
				}
				directorAds.Set(name, info, 15*time.Minute)
			}

			ctx := context.Background()

			type pending struct {
				receiver string
				seenBy   []string
			}

			queue := []pending{{receiver: names[0], seenBy: nil}}
			received := make(map[string]bool, n)
			round := 0

			for len(queue) > 0 {
				round++
				require.LessOrEqual(t, round, n+1,
					"forwarding did not terminate in ≤%d rounds for %d directors", n+1, n)

				for _, pf := range queue {
					directorName = pf.receiver
					forwardServiceAd(ctx, makeTestServiceAd(), server_structs.OriginType, pf.seenBy)
				}

				var nextQueue []pending
				for _, name := range names {
				drain:
					for {
						select {
						case info := <-channels[name]:
							received[name] = true
							data, err := io.ReadAll(info.contents)
							require.NoError(t, err)
							var fwd forwardAd
							require.NoError(t, json.Unmarshal(data, &fwd))
							nextQueue = append(nextQueue, pending{
								receiver: name,
								seenBy:   fwd.SeenBy,
							})
						default:
							break drain
						}
					}
				}
				queue = nextQueue
			}

			// Every director except the originating one must have received the ad.
			for _, name := range names[1:] {
				assert.True(t, received[name],
					"director %s never received the ad in a %d-director topology", name, n)
			}
		})
	}
}
