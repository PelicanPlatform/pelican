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

package htb

import (
	"context"
	"fmt"
	"sync"
	"time"
)

const (
	tickInterval            = 100 * time.Millisecond
	defaultStalenessTimeout = 10 * time.Second // Remove users after 10 seconds of inactivity
)

// HTB represents a hierarchical token bucket rate limiter with two levels:
// a parent bucket and multiple child buckets (one per user).
type HTB struct {
	mu               sync.Mutex
	parent           *bucket
	children         map[string]*bucket
	rate             float64       // tokens per second
	capacity         int64         // total capacity N
	lastTick         time.Time     // time of last tick
	nextChild        int           // for round-robin waiter processing
	childOrder       []string      // stable ordering for round-robin
	stalenessTimeout time.Duration // timeout for removing stale users
}

// bucket represents a single token bucket (parent or child)
type bucket struct {
	tokens   float64
	capacity int64
	waiters  []*waiter
	lastUse  time.Time // last time tokens were taken
}

// waiter represents a goroutine waiting for tokens
type waiter struct {
	n            int64
	ready        chan struct{}
	ctx          context.Context
	becomeLeader chan struct{} // closed when this waiter should become the lead
}

// Tokens represents an allocation of tokens that can be used and returned.
type Tokens struct {
	h      *HTB
	userID string
	taken  int64
	used   int64
}

// Use attempts to use n tokens from the allocation.
// Returns the number of unfulfilled tokens (0 if all tokens were available).
func (t *Tokens) Use(n int64) int64 {
	if n <= 0 {
		return 0
	}
	available := t.taken - t.used
	if n <= available {
		t.used += n
		return 0
	}
	// Use all available
	t.used = t.taken
	return n - available
}

// New creates a new hierarchical token bucket rate limiter.
// rate is in tokens per second, capacity is the total parent bucket size.
func New(rate float64, capacity int64) *HTB {
	if rate <= 0 {
		panic("htb: rate must be positive")
	}
	if capacity <= 0 {
		panic("htb: capacity must be positive")
	}

	h := &HTB{
		parent: &bucket{
			tokens:   float64(capacity),
			capacity: capacity,
			waiters:  make([]*waiter, 0),
		},
		children:         make(map[string]*bucket),
		rate:             rate,
		capacity:         capacity,
		lastTick:         time.Now(),
		childOrder:       make([]string, 0),
		stalenessTimeout: defaultStalenessTimeout,
	}

	return h
}

// maybeTickLocked checks if enough time has passed and performs ticks if needed.
// Must be called with lock held.
func (h *HTB) maybeTickLocked() {
	now := time.Now()
	elapsed := now.Sub(h.lastTick)

	// Calculate how many ticks have passed
	numTicks := int(elapsed / tickInterval)
	if numTicks == 0 {
		return
	}

	// Perform ticks (stop early if system is fully saturated)
	ticksPerformed := 0
	for i := 0; i < numTicks; i++ {
		if !h.tickOnce() {
			// System is fully saturated (all children and parent at capacity)
			break
		}
		ticksPerformed++
	}

	// Update last tick time based on ticks performed
	h.lastTick = h.lastTick.Add(time.Duration(ticksPerformed) * tickInterval)
}

// tickOnce processes one tick: adds tokens, processes waiters, and removes stale users.
// Returns true if more ticks would be useful, false if system is fully saturated.
// Must be called with lock held.
func (h *HTB) tickOnce() bool {

	// Calculate tokens to add per tick
	tokensPerTick := h.rate * tickInterval.Seconds()

	// Remove stale users (not used in stalenessTimeout)
	now := time.Now()
	staleUsers := make([]string, 0)
	for userID, child := range h.children {
		if !child.lastUse.IsZero() && now.Sub(child.lastUse) > h.stalenessTimeout {
			staleUsers = append(staleUsers, userID)
		}
	}
	for _, userID := range staleUsers {
		h.removeUserLocked(userID)
	}

	// Add tokens to each child bucket
	numChildren := len(h.children)
	if numChildren > 0 {
		tokensPerChild := tokensPerTick / float64(numChildren)

		for _, child := range h.children {
			child.tokens += tokensPerChild

			// Get the child's fair share capacity
			childCapacity := h.capacity / int64(numChildren)

			// If child overflows, transfer excess to parent
			if child.tokens > float64(childCapacity) {
				excess := child.tokens - float64(childCapacity)
				child.tokens = float64(childCapacity)

				// Add to parent, but don't overfill
				h.parent.tokens += excess
				if h.parent.tokens > float64(h.parent.capacity) {
					h.parent.tokens = float64(h.parent.capacity)
				}
			}
		}
	} else {
		// No children, add tokens to parent
		h.parent.tokens += tokensPerTick
		if h.parent.tokens > float64(h.parent.capacity) {
			h.parent.tokens = float64(h.parent.capacity)
		}
	}

	// Process waiters in round-robin fashion
	h.processWaiters()

	// Check if system is fully saturated
	// If parent is full and all children are at capacity, no more ticks are needed
	if h.parent.tokens >= float64(h.parent.capacity) {
		numChildren := len(h.children)
		if numChildren > 0 {
			childCapacity := h.capacity / int64(numChildren)
			for _, child := range h.children {
				if child.tokens < float64(childCapacity) {
					// At least one child can still accept tokens
					return true
				}
			}
			// All children at capacity and parent full - system saturated
			return false
		}
		// No children and parent full - system saturated
		return false
	}
	// Parent not full - more ticks useful
	return true
}

// processWaiters tries to satisfy waiting requests in round-robin order
func (h *HTB) processWaiters() {
	if len(h.childOrder) == 0 {
		return
	}

	// Process each child's waiters once, starting from nextChild
	for i := 0; i < len(h.childOrder); i++ {
		idx := (h.nextChild + i) % len(h.childOrder)
		userID := h.childOrder[idx]
		child, exists := h.children[userID]
		if !exists {
			continue
		}

		// Try to satisfy waiters for this child
		h.processChildWaiters(userID, child)
	}

	// Update next child index for next tick
	h.nextChild = (h.nextChild + 1) % len(h.childOrder)
}

// processChildWaiters processes the waiter queue for a specific child
func (h *HTB) processChildWaiters(userID string, child *bucket) {
	newWaiters := make([]*waiter, 0, len(child.waiters))

	for _, w := range child.waiters {
		// Check if context is cancelled
		select {
		case <-w.ctx.Done():
			close(w.ready)
			continue
		default:
		}

		// Try to allocate tokens (allow burst for waiters)
		if h.tryAllocate(child, w.n, true) {
			close(w.ready)
		} else {
			// Keep waiting
			newWaiters = append(newWaiters, w)
		}
	}

	child.waiters = newWaiters
}

// promoteNextLeader promotes the next waiter to lead after the current lead exits.
// Must be called with lock held. The exiting waiter (exitingWaiter) may or may not
// still be in the waiters slice depending on how it exited.
func (h *HTB) promoteNextLeader(child *bucket, exitingWaiter *waiter) {
	// Find and remove the exiting waiter if it's still in the list
	for i, w := range child.waiters {
		if w == exitingWaiter {
			child.waiters = append(child.waiters[:i], child.waiters[i+1:]...)
			break
		}
	}

	// Promote the new first waiter (if any) to lead
	if len(child.waiters) > 0 {
		close(child.waiters[0].becomeLeader)
	}
}

// runLeadWaiterLoop runs the lead waiter ticking loop. Returns Tokens on success, error on context cancellation.
// Must be called WITHOUT lock held.
func (h *HTB) runLeadWaiterLoop(ctx context.Context, userID string, child *bucket, w *waiter, n int64) (*Tokens, error) {
	// Calculate time until next tick based on lastTick
	h.mu.Lock()
	elapsedSinceLastTick := time.Since(h.lastTick)
	timeUntilNextTick := tickInterval - (elapsedSinceLastTick % tickInterval)
	h.mu.Unlock()

	// Use a timer for the first tick at the correct time
	firstTick := time.NewTimer(timeUntilNextTick)
	defer firstTick.Stop()

	// Then use regular ticker for subsequent ticks
	var ticker *time.Ticker
	var tickerC <-chan time.Time

	for {
		select {
		case <-w.ready:
			// Success! Promote next waiter to lead if any
			if ticker != nil {
				ticker.Stop()
			}
			h.mu.Lock()
			h.promoteNextLeader(child, w)
			h.mu.Unlock()
			return &Tokens{h: h, userID: userID, taken: n, used: 0}, nil
		case <-ctx.Done():
			// Cancelled! Promote next waiter to lead if any
			if ticker != nil {
				ticker.Stop()
			}
			h.mu.Lock()
			h.promoteNextLeader(child, w)
			h.mu.Unlock()
			return nil, ctx.Err()
		case <-firstTick.C:
			// First tick at correct time - now create regular ticker
			ticker = time.NewTicker(tickInterval)
			defer ticker.Stop()
			tickerC = ticker.C
			// Process this tick
			h.mu.Lock()
			h.maybeTickLocked()
			if h.tryAllocate(child, n, true) {
				// Success! Promote next waiter to lead
				h.promoteNextLeader(child, w)
				h.mu.Unlock()
				return &Tokens{h: h, userID: userID, taken: n, used: 0}, nil
			}
			h.processChildWaiters(userID, child)
			h.mu.Unlock()
		case <-tickerC:
			// Periodically tick and retry allocation
			h.mu.Lock()
			h.maybeTickLocked()

			// Try to allocate for this waiter
			if h.tryAllocate(child, n, true) {
				// Success! Promote next waiter to lead
				h.promoteNextLeader(child, w)
				h.mu.Unlock()
				return &Tokens{h: h, userID: userID, taken: n, used: 0}, nil
			}

			// Also try to wake other waiters if possible
			h.processChildWaiters(userID, child)
			h.mu.Unlock()
		}
	}
}

// tryAllocate attempts to allocate n tokens from the child bucket,
// borrowing from parent if needed. Supports burst by allowing negative balances.
func (h *HTB) tryAllocate(child *bucket, n int64, allowBurst bool) bool {
	needed := float64(n)

	// First, use child's tokens if it has enough
	if child.tokens >= needed {
		child.tokens -= needed
		child.lastUse = time.Now()
		return true
	}

	// Child doesn't have enough, try to borrow from parent
	childHas := child.tokens
	needFromParent := needed - childHas

	// If parent has enough, borrow it (this is normal hierarchical behavior)
	if h.parent.tokens >= needFromParent {
		child.tokens = 0
		h.parent.tokens -= needFromParent
		child.lastUse = time.Now()
		return true
	}

	// Not enough tokens available even with parent, check if we can burst (go negative)
	if allowBurst && n <= h.capacity {
		// Calculate what child could have if it were full
		potentialTokens := childHas + h.parent.tokens

		// Allow burst if child could be full with parent tokens
		if potentialTokens >= float64(child.capacity) {
			// Go negative
			deficit := needed - childHas - h.parent.tokens
			child.tokens = -deficit
			h.parent.tokens = 0
			child.lastUse = time.Now()
			return true
		}
	}

	// Not enough tokens available
	return false
}

// Wait blocks until n tokens are available for the specified user.
// Returns a Tokens object that can be used to track token usage, or an error if the context is cancelled.
func (h *HTB) Wait(ctx context.Context, userID string, n int64) (*Tokens, error) {
	if n <= 0 {
		return &Tokens{h: h, userID: userID, taken: 0, used: 0}, nil
	}
	if n > h.capacity {
		return nil, fmt.Errorf("htb: requested tokens (%d) exceed capacity (%d)", n, h.capacity)
	}

	h.mu.Lock()

	// Update tokens based on elapsed time
	h.maybeTickLocked()

	// Ensure child bucket exists
	child, exists := h.children[userID]
	if !exists {
		child = h.addChild(userID)
	}

	// Try immediate allocation (allow burst)
	if h.tryAllocate(child, n, true) {
		h.mu.Unlock()
		return &Tokens{h: h, userID: userID, taken: n, used: 0}, nil
	}

	// Need to wait - check if this will be the lead waiter
	isLeadWaiter := len(child.waiters) == 0
	w := &waiter{
		n:            n,
		ready:        make(chan struct{}),
		ctx:          ctx,
		becomeLeader: make(chan struct{}),
	}
	child.waiters = append(child.waiters, w)
	h.mu.Unlock()

	// Lead waiter must periodically tick since there's no background goroutine
	// This ensures forward progress when all goroutines are waiting
	if isLeadWaiter {
		return h.runLeadWaiterLoop(ctx, userID, child, w, n)
	}

	// Non-lead waiters wait for their channel or to become the lead
	for {
		select {
		case <-w.ready:
			return &Tokens{h: h, userID: userID, taken: n, used: 0}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-w.becomeLeader:
			// We've been promoted to lead!
			return h.runLeadWaiterLoop(ctx, userID, child, w, n)
		}
	}
}

// TryTake attempts to take n tokens for the specified user without blocking.
// Returns a Tokens object if successful, nil otherwise.
func (h *HTB) TryTake(userID string, n int64) *Tokens {
	if n <= 0 {
		return &Tokens{h: h, userID: userID, taken: 0, used: 0}
	}
	if n > h.capacity {
		return nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// Update tokens based on elapsed time
	h.maybeTickLocked()

	// Ensure child bucket exists
	child, exists := h.children[userID]
	if !exists {
		child = h.addChild(userID)
	}

	if h.tryAllocate(child, n, true) {
		return &Tokens{h: h, userID: userID, taken: n, used: 0}
	}
	return nil
}

// Return returns unused tokens from a Tokens object to the specified user's bucket.
// This is used when a request took more tokens than needed.
func (h *HTB) Return(tokens *Tokens) {
	if tokens == nil {
		return
	}

	unused := tokens.taken - tokens.used
	if unused <= 0 {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	child, exists := h.children[tokens.userID]
	if !exists {
		// If child doesn't exist, return to parent
		h.parent.tokens += float64(unused)
		if h.parent.tokens > float64(h.parent.capacity) {
			h.parent.tokens = float64(h.parent.capacity)
		}
		// Process waiters for all children since parent got tokens
		h.processAllWaiters()
		return
	}

	// Add tokens to child
	child.tokens += float64(unused)

	// Get the child's fair share capacity
	numChildren := len(h.children)
	childCapacity := h.capacity / int64(numChildren)

	// If child overflows, transfer excess to parent
	if child.tokens > float64(childCapacity) {
		excess := child.tokens - float64(childCapacity)
		child.tokens = float64(childCapacity)

		// Add to parent, but don't overfill
		h.parent.tokens += excess
		if h.parent.tokens > float64(h.parent.capacity) {
			h.parent.tokens = float64(h.parent.capacity)
		}
	}

	// Try to process waiters for this child and potentially others
	h.processChildWaiters(tokens.userID, child)

	// If we added tokens to parent, also try other children's waiters
	if child.tokens >= float64(childCapacity) || h.parent.tokens > 0 {
		h.processAllWaiters()
	}
}

// processAllWaiters processes waiters for all children (must be called with lock held)
func (h *HTB) processAllWaiters() {
	for userID, child := range h.children {
		if len(child.waiters) > 0 {
			h.processChildWaiters(userID, child)
		}
	}
}

// addChild adds a new child bucket for a user (must be called with lock held)
func (h *HTB) addChild(userID string) *bucket {
	numChildren := len(h.children) + 1
	childCapacity := h.capacity / int64(numChildren)

	child := &bucket{
		tokens:   float64(childCapacity),
		capacity: childCapacity,
		waiters:  make([]*waiter, 0),
		// lastUse is zero - will be set on first actual use
	}

	h.children[userID] = child
	h.childOrder = append(h.childOrder, userID)

	// Rebalance all children's capacities and transfer excess to parent
	for _, c := range h.children {
		c.capacity = childCapacity

		// If child now has more tokens than new capacity, transfer excess to parent
		if c.tokens > float64(childCapacity) {
			excess := c.tokens - float64(childCapacity)
			c.tokens = float64(childCapacity)
			h.parent.tokens += excess
		}
	}

	// Cap parent tokens at parent capacity
	if h.parent.tokens > float64(h.parent.capacity) {
		h.parent.tokens = float64(h.parent.capacity)
	}

	return child
}

// removeUserLocked removes a user's bucket and returns any remaining tokens to the parent.
// Must be called with lock held.
func (h *HTB) removeUserLocked(userID string) {

	child, exists := h.children[userID]
	if !exists {
		return
	}

	// Return child's tokens to parent
	h.parent.tokens += child.tokens
	if h.parent.tokens > float64(h.parent.capacity) {
		h.parent.tokens = float64(h.parent.capacity)
	}

	// Cancel any waiting requests
	for _, w := range child.waiters {
		close(w.ready)
	}

	// Remove child
	delete(h.children, userID)

	// Remove from childOrder
	newOrder := make([]string, 0, len(h.childOrder)-1)
	for _, id := range h.childOrder {
		if id != userID {
			newOrder = append(newOrder, id)
		}
	}
	h.childOrder = newOrder

	// Rebalance remaining children's capacities
	numChildren := len(h.children)
	if numChildren > 0 {
		childCapacity := h.capacity / int64(numChildren)
		for _, c := range h.children {
			c.capacity = childCapacity
		}
	}
}

// Close stops the HTB and releases resources.
func (h *HTB) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Cancel all waiters
	for _, child := range h.children {
		for _, w := range child.waiters {
			close(w.ready)
		}
	}
}

// Stats returns statistics about the current state of the HTB
type Stats struct {
	ParentTokens  float64
	NumChildren   int
	ChildrenStats map[string]ChildStats
}

type ChildStats struct {
	Tokens     float64
	Capacity   int64
	NumWaiters int
}

// GetStats returns current statistics about the HTB
func (h *HTB) GetStats() Stats {
	h.mu.Lock()
	defer h.mu.Unlock()

	stats := Stats{
		ParentTokens:  h.parent.tokens,
		NumChildren:   len(h.children),
		ChildrenStats: make(map[string]ChildStats),
	}

	for userID, child := range h.children {
		stats.ChildrenStats[userID] = ChildStats{
			Tokens:     child.tokens,
			Capacity:   child.capacity,
			NumWaiters: len(child.waiters),
		}
	}

	return stats
}
