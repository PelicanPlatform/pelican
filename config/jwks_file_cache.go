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

package config

import (
	"io"
	"os"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	// MaxJWKSFileSize bounds how much of an operator-supplied JWKS file is
	// read. A JWKS holding even a few dozen RSA-4096 keys is well under this,
	// so the limit only ever trips on a wrong path or a corrupt file, and it
	// keeps an unauthenticated request that triggers a read from turning the
	// file's size into the server's memory usage.
	MaxJWKSFileSize = 1 << 20 // 1 MiB

	// jwksFileCacheTTL is the minimum interval between filesystem reads of the
	// same JWKS file. The public JWKS endpoints are unauthenticated, so without
	// throttling every request would stat, read, parse, and project the file.
	// Five seconds keeps an edit visible almost immediately while making the
	// request rate irrelevant to the I/O rate.
	jwksFileCacheTTL = 5 * time.Second
)

type jwksFileCacheEntry struct {
	// keys is the last public projection that loaded successfully, or nil if
	// no version of this file has ever loaded. It is retained so that a torn
	// read of a file being rewritten in place can fall back to it.
	keys jwk.Set
	// err is the outcome of the most recent read attempt, or nil on success.
	// Failures are cached alongside successes so that a persistently broken
	// file is not re-read on every request.
	err error
	// checkedAt is when the most recent read attempt happened.
	checkedAt time.Time
}

var (
	jwksFileCacheMu sync.Mutex
	jwksFileCache   = map[string]*jwksFileCacheEntry{}

	// jwksFileCacheNow is the clock used for TTL decisions. It is a variable
	// so that tests can advance time without sleeping.
	jwksFileCacheNow = time.Now

	jwksIssueMu sync.Mutex

	// jwksIssueState remembers, per scope and issue kind, the last signature
	// reported. A misconfiguration that persists is worth one log line per
	// change, not one per cache refresh -- and, on the unauthenticated JWKS
	// endpoints, not one per request, or any client could turn its own request
	// rate into the server's log rate.
	jwksIssueState = map[JWKSScope]map[string]string{}
)

// JWKSScope identifies what a reported JWKS problem belongs to.
type JWKSScope string

func JWKSFileScope(path string) JWKSScope {
	return JWKSScope("fs-path:" + path)
}

func JWKSNamespaceScope(prefix string) JWKSScope {
	return JWKSScope("namespace:" + prefix)
}

const JWKSServerKeysScope JWKSScope = "server-keys:"

const (
	// Failure to load the server's own key set.
	JWKSKindBaseKeys = "base-jwks"
	// A per-namespace IssuerJwks file that cannot be published.
	JWKSKindNamespaceExtra = "extra-jwks"
	// A JWKS file that will not load while a previous good version is still being served.
	jwksKindStaleFallback = "stale-fallback"
)

// ResetJWKSFileCache drops all cached JWKS file contents and the record of
// which problems have already been reported. Called from ResetConfig so that a
// test writing a new file at a path a previous test already used sees the new
// contents rather than a cached projection.
func ResetJWKSFileCache() {
	jwksFileCacheMu.Lock()
	jwksFileCache = map[string]*jwksFileCacheEntry{}
	jwksFileCacheMu.Unlock()

	jwksIssueMu.Lock()
	jwksIssueState = map[JWKSScope]map[string]string{}
	jwksIssueMu.Unlock()
}

// LogJWKSIssueOnChange logs at the given level the first time it sees
// signature for the given scope and kind, and thereafter only when signature
// changes. Callers on a per-request path use this so that a standing
// misconfiguration costs one log line per change rather than one per request.
//
// kind identifies which problem it is, and signature is the part that should
// re-report when it changes -- usually err.Error(). Every scope must be
// derived from configuration and never from request input, so that what this
// accumulates stays bounded.
//
// The level is a parameter rather than fixed at warning because the same
// throttling applies to conditions of different severity, and no caller should
// have to choose between logging at the right level and logging at the right
// frequency.
func LogJWKSIssueOnChange(level log.Level, scope JWKSScope, kind, signature, format string, args ...interface{}) {
	jwksIssueMu.Lock()
	if byKind := jwksIssueState[scope]; byKind != nil {
		if prev, ok := byKind[kind]; ok && prev == signature {
			jwksIssueMu.Unlock()
			return
		}
	} else {
		jwksIssueState[scope] = map[string]string{}
	}
	jwksIssueState[scope][kind] = signature
	jwksIssueMu.Unlock()

	// logrus has no package-level Logf, so go through the standard logger.
	log.StandardLogger().Logf(level, format, args...)
}

// ForgetJWKSIssue drops any remembered report for the given scope and kind, so
// that the next occurrence is logged again even if it carries a signature that
// was already reported. Callers invoke it once they observe the condition
// resolved; without it, a problem that is fixed and later recurs identically
// stays silent for the rest of the process's life.
//
// A request that observes the condition resolved can interleave with one that
// hits it. The map is guarded, so nothing is corrupted, and at worst a single
// duplicate or missing line appears at the instant the state flips -- the
// condition is re-evaluated on the next request either way.
func ForgetJWKSIssue(scope JWKSScope, kind string) {
	jwksIssueMu.Lock()
	defer jwksIssueMu.Unlock()

	byKind := jwksIssueState[scope]
	if byKind == nil {
		return
	}
	delete(byKind, kind)
	if len(byKind) == 0 {
		delete(jwksIssueState, scope)
	}
}

// logJWKSWarningOnChange is LogJWKSIssueOnChange at warning level, for the
// readers in this package: each reports a condition the server keeps running
// through.
func logJWKSWarningOnChange(scope JWKSScope, kind, signature, format string, args ...interface{}) {
	LogJWKSIssueOnChange(log.WarnLevel, scope, kind, signature, format, args...)
}

// readPublicJWKSFileCached returns the public projection of the JWKS file at
// path, reading the file at most once per jwksFileCacheTTL.
//
// A file that exists and is non-empty but does not load -- a torn read of a
// rewrite in progress, a corrupt document, an unpublishable key, or a file
// past MaxJWKSFileSize -- falls back to the last version that loaded
// successfully, if there is one, so that rewriting a key file in place cannot
// momentarily drop a namespace's keys. A missing or zero-length file gets no
// fallback: that is an unambiguous "these keys are gone" signal rather than a
// transient read, and the remembered good version is discarded so a later
// torn read cannot resurrect it.
//
// The returned set is shared with every other caller for the same path and
// must be treated as read-only; callers that need to add keys must copy it
// into a set of their own first.
func readPublicJWKSFileCached(path string) (jwk.Set, error) {
	jwksFileCacheMu.Lock()
	defer jwksFileCacheMu.Unlock()

	now := jwksFileCacheNow()
	entry := jwksFileCache[path]
	if entry != nil && now.Sub(entry.checkedAt) < jwksFileCacheTTL {
		return entry.keys, entry.err
	}

	keys, nonEmpty, err := loadPublicJWKSFile(path)
	if err != nil {
		if nonEmpty && entry != nil && entry.keys != nil {
			logJWKSWarningOnChange(JWKSFileScope(path), jwksKindStaleFallback, err.Error(),
				"JWKS file %s is present but could not be loaded; continuing to use the "+
					"last version that loaded successfully. Until this is fixed, edits to "+
					"the file will not take effect: %v", path, err)
			entry.checkedAt = now
			return entry.keys, nil
		}
		jwksFileCache[path] = &jwksFileCacheEntry{err: err, checkedAt: now}
		return nil, err
	}
	// The file loads again, so forget any stale-fallback complaint.
	ForgetJWKSIssue(JWKSFileScope(path), jwksKindStaleFallback)
	jwksFileCache[path] = &jwksFileCacheEntry{keys: keys, checkedAt: now}
	return keys, nil
}

// loadPublicJWKSFile reads, validates, and publicly projects the JWKS file at
// path without consulting the cache.
//
// nonEmpty reports whether the file existed and held at least one byte. The
// caller uses it to tell a file that is mid-rewrite or corrupt (worth falling
// back to the previous contents for) from one that is missing or truncated to
// nothing (not worth it).
func loadPublicJWKSFile(path string) (set jwk.Set, nonEmpty bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, errors.Wrapf(err, "failed to open JWKS file %s", path)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, false, errors.Wrapf(err, "failed to stat JWKS file %s", path)
	}
	if !fi.Mode().IsRegular() {
		return nil, false, errors.Errorf("JWKS file %s is not a regular file", path)
	}
	warnIfJWKSFileWorldWritable(path, fi.Mode().Perm())
	// Check the stat size first so an oversized file is rejected without
	// reading it at all.
	if fi.Size() > MaxJWKSFileSize {
		return nil, true, errors.Errorf("JWKS file %s is %d bytes, which exceeds the %d-byte limit",
			path, fi.Size(), MaxJWKSFileSize)
	}

	// Bound the read independently of the stat above: the file may have grown
	// between the two, and on some filesystems the reported size is a hint.
	data, err := io.ReadAll(io.LimitReader(f, MaxJWKSFileSize+1))
	if err != nil {
		return nil, fi.Size() > 0, errors.Wrapf(err, "failed to read JWKS file %s", path)
	}
	if len(data) > MaxJWKSFileSize {
		return nil, true, errors.Errorf("JWKS file %s exceeds the %d-byte limit", path, MaxJWKSFileSize)
	}
	if len(data) == 0 {
		return nil, false, errors.Errorf("JWKS file %s is empty", path)
	}

	raw, err := jwk.Parse(data)
	if err != nil {
		return nil, true, errors.Wrapf(err, "failed to parse JWKS file %s", path)
	}
	out, err := stripPrivateKeys(raw)
	if err != nil {
		return nil, true, errors.Wrapf(err, "JWKS file %s is invalid", path)
	}
	return out, true, nil
}
