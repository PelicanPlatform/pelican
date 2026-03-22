/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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

package local_cache

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/token_scopes"
)

// ---- Prestage worker pool ----

const (
	// Default maximum number of concurrent prestage workers per identity.
	defaultPrestageMaxWorkers = 20
	// Default maximum pending prestage operations per identity.
	defaultPrestageMaxPending = 20
	// How long an idle identity pool lives before being cleaned up.
	defaultPrestageIdleTimeout = time.Minute
	// Read buffer size used when draining the cached object.
	prestageReadBufSize = 64 * 1024
)

// prestageRequest is a single queued prestage operation.
type prestageRequest struct {
	path  string
	token string

	// Written by the worker goroutine.
	progress int64 // bytes read so far (atomic-free: only one writer)

	mu      sync.Mutex
	cv      *sync.Cond
	status  int    // HTTP status code when done (0 => still in progress, <0 => queued/active)
	message string // result message
	active  bool   // true once a worker picks this up
}

func newPrestageRequest(path, token string) *prestageRequest {
	r := &prestageRequest{
		path:   path,
		token:  token,
		status: -1, // queued
	}
	r.cv = sync.NewCond(&r.mu)
	return r
}

// SetDone records the final result and wakes the waiter.
func (r *prestageRequest) SetDone(status int, msg string) {
	r.mu.Lock()
	r.status = status
	r.message = msg
	r.mu.Unlock()
	r.cv.Broadcast()
}

// WaitFor blocks until the request is done or the timeout elapses.
// Returns the status code (>0 when done, <=0 when still in progress).
// A WaitGroup ensures any timer goroutine has finished before returning.
func (r *prestageRequest) WaitFor(d time.Duration) int {
	deadline := time.Now().Add(d)
	var wg sync.WaitGroup
	r.mu.Lock()
	defer func() {
		r.mu.Unlock()
		wg.Wait()
	}()
	for r.status <= 0 {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return r.status
		}
		// Use a timer-based goroutine to bound how long cv.Wait blocks.
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(remaining)
			r.cv.Broadcast()
		}()
		r.cv.Wait()
	}
	return r.status
}

// prestageQueue is a per-identity queue of prestage requests with a pool
// of worker goroutines.
type prestageQueue struct {
	ident   string
	pc      *PersistentCache
	manager *PrestageManager

	mu      sync.Mutex
	ops     []*prestageRequest
	workers int
	idle    int
	wake    chan struct{} // signalled when a new op is enqueued
	done    bool
}

func newPrestageQueue(ident string, pc *PersistentCache, mgr *PrestageManager) *prestageQueue {
	return &prestageQueue{
		ident:   ident,
		pc:      pc,
		manager: mgr,
		wake:    make(chan struct{}, 1),
	}
}

// Produce enqueues a request, returning false if the queue is full.
func (q *prestageQueue) Produce(req *prestageRequest) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.ops) >= q.manager.maxPending {
		return false
	}
	q.ops = append(q.ops, req)

	// Wake an idle worker if available.
	if q.idle > 0 {
		select {
		case q.wake <- struct{}{}:
		default:
		}
		return true
	}

	// Spawn a new worker if under the limit.
	if q.workers < q.manager.maxWorkers {
		q.workers++
		go q.runWorker()
	}
	return true
}

// tryConsume pops the next request if one is available.
func (q *prestageQueue) tryConsume() *prestageRequest {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.ops) == 0 {
		return nil
	}
	req := q.ops[0]
	q.ops = q.ops[1:]
	return req
}

// runWorker is the main loop of a prestage worker goroutine.
func (q *prestageQueue) runWorker() {
	log.Infof("Prestage worker for identity %q starting", q.ident)
	defer func() {
		q.mu.Lock()
		q.workers--
		if q.workers == 0 && len(q.ops) == 0 {
			q.done = true
			q.mu.Unlock()
			q.manager.removeQueue(q.ident)
		} else {
			q.mu.Unlock()
		}
		log.Infof("Prestage worker for identity %q exiting", q.ident)
	}()

	for {
		req := q.tryConsume()
		if req == nil {
			// Wait for work or idle timeout.
			q.mu.Lock()
			q.idle++
			q.mu.Unlock()

			timer := time.NewTimer(q.manager.idleTimeout)
			select {
			case <-q.wake:
				timer.Stop()
			case <-timer.C:
				q.mu.Lock()
				q.idle--
				q.mu.Unlock()
				return
			}

			q.mu.Lock()
			q.idle--
			q.mu.Unlock()

			req = q.tryConsume()
			if req == nil {
				continue
			}
		}

		q.prestage(req)
	}
}

// prestage performs the actual cache pull for a single request.
func (q *prestageQueue) prestage(req *prestageRequest) {
	req.mu.Lock()
	req.active = true
	req.mu.Unlock()

	log.Debugf("Prestage worker handling request for %s", req.path)

	// Fast path: if the object is already fully cached, skip the
	// expensive Get+drain cycle entirely.
	if q.pc.IsFullyCached(context.Background(), req.path, req.token) {
		log.Debugf("Prestage: object already fully cached, skipping download: %s", req.path)
		req.SetDone(200, "Prestage successful")
		return
	}

	reader, err := q.pc.Get(context.Background(), req.path, req.token)
	if err != nil {
		status := 500
		msg := err.Error()
		var sce *statusCodeErr
		if errors.As(err, &sce) {
			status = sce.code
		} else if errors.Is(err, authorizationDenied) {
			status = 403
			msg = "Permission denied"
		}
		req.SetDone(status, msg)
		return
	}
	defer reader.Close()

	// Read the entire object to force a full cache pull.
	buf := make([]byte, prestageReadBufSize)
	var off int64
	for {
		n, readErr := reader.Read(buf)
		off += int64(n)
		req.progress = off
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			req.SetDone(500, fmt.Sprintf("I/O failure when prestaging: %v", readErr))
			return
		}
	}

	log.Debugf("Prestage request successful for %s (%d bytes)", req.path, off)
	req.SetDone(200, "Prestage successful")
}

// statusCodeErr is a simple error that carries an HTTP status code.
type statusCodeErr struct {
	code int
	msg  string
}

func (e *statusCodeErr) Error() string { return e.msg }

// PrestageManager manages per-identity worker pools for prestage operations.
type PrestageManager struct {
	pc *PersistentCache

	mu     sync.Mutex
	queues map[string]*prestageQueue

	maxWorkers  int
	maxPending  int
	idleTimeout time.Duration
}

// NewPrestageManager creates a prestage manager for the given cache.
func NewPrestageManager(pc *PersistentCache) *PrestageManager {
	return &PrestageManager{
		pc:          pc,
		queues:      make(map[string]*prestageQueue),
		maxWorkers:  defaultPrestageMaxWorkers,
		maxPending:  defaultPrestageMaxPending,
		idleTimeout: defaultPrestageIdleTimeout,
	}
}

// Submit queues a prestage request for the given identity.
// Returns false if the queue is full (caller should return 429).
func (pm *PrestageManager) Submit(ident string, req *prestageRequest) bool {
	pm.mu.Lock()
	q, ok := pm.queues[ident]
	if !ok || q.done {
		q = newPrestageQueue(ident, pm.pc, pm)
		pm.queues[ident] = q
	}
	pm.mu.Unlock()
	return q.Produce(req)
}

func (pm *PrestageManager) removeQueue(ident string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if q, ok := pm.queues[ident]; ok && q.done {
		delete(pm.queues, ident)
		log.Infof("Prestage queue for identity %q cleaned up", ident)
	}
}

// ---- HTTP handlers ----

// extractBearerToken extracts a bearer token from the request,
// checking both Authorization header and authz query parameter.
func extractBearerToken(r *http.Request) string {
	authz := r.Header.Get("Authorization")
	if strings.HasPrefix(authz, "Bearer ") {
		return authz[7:]
	}
	if q := r.URL.Query().Get("authz"); q != "" {
		return strings.TrimPrefix(q, "Bearer ")
	}
	return ""
}

// extractIdentity returns a label for per-user queuing.
// In the C++ reference this combines VO + token subject; here we use
// the bearer token hash (or "anonymous") since we don't decode the JWT
// on the cache side.
func extractIdentity(token string) string {
	if token == "" {
		return "anonymous"
	}
	// Use a simple hash of the token to group requests by user.
	// This avoids JWT decoding on every request.
	h := uint64(0)
	for _, b := range []byte(token) {
		h = h*31 + uint64(b)
	}
	return fmt.Sprintf("user-%x", h)
}

// prestageHandler handles GET /pelican/api/v1.0/prestage
func (pc *PersistentCache) prestageHandler(w http.ResponseWriter, r *http.Request) {
	pathParam := r.URL.Query().Get("path")
	if pathParam == "" {
		http.Error(w, "Prestage command request requires the `path` query parameter", http.StatusBadRequest)
		return
	}

	decodedPath, err := url.QueryUnescape(pathParam)
	if err != nil {
		http.Error(w, "Failed to unquote `path` query parameter value", http.StatusBadRequest)
		return
	}

	decodedPath = path.Clean(decodedPath)
	if !path.IsAbs(decodedPath) {
		http.Error(w, "Prestage request must be an absolute path", http.StatusBadRequest)
		return
	}

	token := extractBearerToken(r)

	// Check authorization (read permission).
	if ok, reason := pc.ac.authorize(token_scopes.Wlcg_Storage_Read, decodedPath, token); !ok {
		log.WithFields(log.Fields{"path": decodedPath, "reason": reason}).Warn("Prestage authorization denied")
		http.Error(w, "Permission denied to prestage path", http.StatusForbidden)
		return
	}

	ident := extractIdentity(token)
	req := newPrestageRequest(decodedPath, token)

	// Submit to the per-identity worker pool.
	if !pc.prestageManager.Submit(ident, req) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "Too many prestage requests at server", http.StatusTooManyRequests)
		return
	}

	// Stream chunked progress updates until the request completes.
	flusher, ok := w.(http.Flusher)
	if !ok {
		// Fallback: wait for completion and send a single response.
		status := req.WaitFor(5 * time.Minute)
		if status <= 0 {
			http.Error(w, "Prestage timed out", http.StatusGatewayTimeout)
			return
		}
		if status >= 300 {
			http.Error(w, fmt.Sprintf("failure: %d: %s", status, req.message), status)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "success: ok\n")
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.WriteHeader(http.StatusOK)

	for {
		status := req.WaitFor(2 * time.Second)
		if status > 0 {
			// Request is done.
			if status >= 300 {
				desc := http.StatusText(status)
				if desc == "" {
					desc = fmt.Sprintf("%d", status)
				}
				line := fmt.Sprintf("failure: %d(%s): %s\n", status, desc, req.message)
				fmt.Fprint(w, line)
			} else {
				fmt.Fprint(w, "success: ok\n")
			}
			flusher.Flush()
			return
		}

		// Still in progress — send a status update.
		var line string
		req.mu.Lock()
		active := req.active
		req.mu.Unlock()
		if active {
			line = fmt.Sprintf("status: active,offset=%d\n", req.progress)
		} else {
			line = "status: queued\n"
		}
		if _, writeErr := fmt.Fprint(w, line); writeErr != nil {
			log.Debugf("Prestage client disconnected for %s: %v", req.path, writeErr)
			return
		}
		flusher.Flush()
	}
}

// evictHandler handles GET /pelican/api/v1.0/evict
//
// By default, matching objects are marked for priority eviction (purge-first)
// so they will be removed during the next eviction cycle.  Pass
// immediate=true to delete them right away.
func (pc *PersistentCache) evictHandler(w http.ResponseWriter, r *http.Request) {
	pathParam := r.URL.Query().Get("path")
	if pathParam == "" {
		http.Error(w, "Eviction request requires the `path` query parameter", http.StatusBadRequest)
		return
	}

	decodedPath, err := url.QueryUnescape(pathParam)
	if err != nil {
		http.Error(w, "Failed to unquote `path` query parameter value", http.StatusBadRequest)
		return
	}

	decodedPath = path.Clean(decodedPath)
	if !path.IsAbs(decodedPath) {
		http.Error(w, "Eviction request must be an absolute path", http.StatusBadRequest)
		return
	}

	immediate := r.URL.Query().Get("immediate") == "true"

	token := extractBearerToken(r)

	// Check authorization — eviction is a destructive operation so we
	// require storage.modify scope for the target path.
	if ok, reason := pc.ac.authorize(token_scopes.Wlcg_Storage_Modify, decodedPath, token); !ok {
		log.WithFields(log.Fields{"path": decodedPath, "reason": reason}).Warn("Evict authorization denied")
		http.Error(w, "Permission denied to evict path", http.StatusForbidden)
		return
	}

	count, evictErr := pc.EvictPrefix(decodedPath, token, immediate)
	if evictErr != nil {
		log.Warnf("Failed to evict prefix %s: %v", decodedPath, evictErr)
		http.Error(w, "Eviction operation failed", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	if immediate {
		fmt.Fprintf(w, "Evicted %d objects under %s", count, decodedPath)
	} else {
		fmt.Fprintf(w, "Marked %d objects for priority eviction under %s", count, decodedPath)
	}
}

// EvictObject is the programmatic API for evicting an object by path.
// Returns nil on success, an error if the object is in use or the eviction fails.
func (pc *PersistentCache) EvictObject(objectPath, token string) error {
	if ok, reason := pc.ac.authorize(token_scopes.Wlcg_Storage_Modify, objectPath, token); !ok {
		return newAuthorizationDenied(reason)
	}

	pelicanURL := pc.normalizePath(objectPath)
	objectHash := pc.db.ObjectHash(pelicanURL)

	pc.activeDownloadsMu.RLock()
	_, inUse := pc.activeDownloads[objectHash]
	pc.activeDownloadsMu.RUnlock()
	if inUse {
		return errors.New("object is in use")
	}

	etag, found, err := pc.db.GetLatestETag(objectHash)
	if err != nil {
		return errors.Wrap(err, "failed to look up ETag")
	}
	if !found {
		return nil // not in cache, nothing to evict
	}

	instanceHash := pc.db.InstanceHash(etag, objectHash)
	if err := pc.storage.Delete(instanceHash); err != nil {
		return errors.Wrap(err, "failed to delete object")
	}

	if delErr := pc.db.DeleteLatestETag(objectHash); delErr != nil {
		log.Warnf("Failed to delete ETag mapping during eviction: %v", delErr)
	}

	return nil
}

// EvictPrefix evicts all cached objects whose source URL starts with the
// given path prefix (or matches it exactly).  It iterates every metadata
// entry, selects those with a matching SourceURL, and either deletes them
// immediately or marks them for priority eviction (purge-first) depending
// on the immediate flag.  Objects that are currently being downloaded are
// skipped.  The returned count reflects objects that were acted on.
func (pc *PersistentCache) EvictPrefix(prefix, token string, immediate bool) (int, error) {
	normalizedPrefix := pc.normalizePath(prefix)
	// Ensure prefix matching uses a directory boundary.
	if !strings.HasSuffix(normalizedPrefix, "/") {
		normalizedPrefix += "/"
	}

	var affected int
	var firstErr error

	err := pc.db.ScanMetadata(func(instanceHash InstanceHash, meta *CacheMetadata) error {
		// Check if the SourceURL starts with the normalized prefix, or
		// matches the prefix exactly (without trailing slash).
		if !strings.HasPrefix(meta.SourceURL, normalizedPrefix) &&
			meta.SourceURL != strings.TrimSuffix(normalizedPrefix, "/") {
			return nil
		}

		// Skip objects being actively downloaded.
		objectHash := pc.db.ObjectHash(meta.SourceURL)
		pc.activeDownloadsMu.RLock()
		_, inUse := pc.activeDownloads[objectHash]
		pc.activeDownloadsMu.RUnlock()
		if inUse {
			log.Debugf("Skipping in-use object during prefix eviction: %s", meta.SourceURL)
			return nil
		}

		if immediate {
			if delErr := pc.storage.Delete(instanceHash); delErr != nil {
				log.Warnf("Failed to evict %s during prefix eviction: %v", meta.SourceURL, delErr)
				if firstErr == nil {
					firstErr = delErr
				}
				return nil // continue with other objects
			}
			if delErr := pc.db.DeleteLatestETag(objectHash); delErr != nil {
				log.Warnf("Failed to delete ETag mapping for %s: %v", meta.SourceURL, delErr)
			}
			log.Debugf("Evicted cached object (prefix eviction): %s", meta.SourceURL)
		} else {
			if markErr := pc.eviction.MarkPurgeFirst(instanceHash); markErr != nil {
				log.Warnf("Failed to mark %s for priority eviction: %v", meta.SourceURL, markErr)
				if firstErr == nil {
					firstErr = markErr
				}
				return nil
			}
			log.Debugf("Marked for priority eviction (prefix): %s", meta.SourceURL)
		}

		affected++
		return nil
	})

	if err != nil {
		return affected, errors.Wrap(err, "metadata scan failed during prefix eviction")
	}
	if firstErr != nil {
		return affected, errors.Wrapf(firstErr, "processed %d objects but some failed", affected)
	}
	return affected, nil
}
