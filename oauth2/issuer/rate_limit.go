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

package issuer

import (
	"net"
	"sync"
	"time"
)

// registrationRateLimiter enforces per-IP rate limiting on the dynamic client
// registration endpoint.  It uses a simple token-bucket approach: each IP
// address is allowed `burst` registrations, replenished at `rate` per second.
type registrationRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens per second
	burst   int     // maximum tokens (= burst size)
}

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// newRegistrationRateLimiter creates a rate limiter that allows `burst`
// registrations immediately and then refills at `rate` per second.
func newRegistrationRateLimiter(rate float64, burst int) *registrationRateLimiter {
	return &registrationRateLimiter{
		buckets: make(map[string]*bucket),
		rate:    rate,
		burst:   burst,
	}
}

// normalizeIP returns a rate-limit key for the given IP string.
// IPv4 addresses are returned as-is.  IPv6 addresses are masked to
// a /64 prefix because a single end-site typically owns an entire /64
// block — rate limiting individual IPv6 addresses would be trivially
// bypassed by rotating through the block.
func normalizeIP(raw string) string {
	ip := net.ParseIP(raw)
	if ip == nil {
		return raw // unparseable; use the string verbatim
	}
	if ip.To4() != nil {
		return ip.String() // IPv4 — per-address is fine
	}
	// IPv6 — mask to /64
	masked := ip.Mask(net.CIDRMask(64, 128))
	return masked.String() + "/64"
}

// Allow reports whether a registration from the given IP is allowed.
// Returns false if the rate limit has been exceeded.
// IPv6 addresses are aggregated to their /64 prefix so that an attacker
// cannot bypass the limit by rotating through addresses in a single block.
func (rl *registrationRateLimiter) Allow(ip string) bool {
	key := normalizeIP(ip)
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	b, ok := rl.buckets[key]
	if !ok {
		// First request — start with burst-1 tokens (we're consuming one now)
		rl.buckets[key] = &bucket{
			tokens:   float64(rl.burst) - 1,
			lastSeen: now,
		}
		return true
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens += elapsed * rl.rate
	if b.tokens > float64(rl.burst) {
		b.tokens = float64(rl.burst)
	}
	b.lastSeen = now

	if b.tokens < 1 {
		return false
	}

	b.tokens--
	return true
}

// Cleanup removes stale entries older than maxAge.
// Should be called periodically to prevent unbounded memory growth.
func (rl *registrationRateLimiter) Cleanup(maxAge time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for ip, b := range rl.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(rl.buckets, ip)
		}
	}
}
