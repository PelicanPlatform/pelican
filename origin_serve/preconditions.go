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

// Conditional-write preconditions (RFC 9110 §13.1).
//
// golang.org/x/net/webdav does not implement If-Match or If-None-Match --
// there is an explicit TODO in its handlePut -- so a client asking for
// compare-and-swap or create-only semantics is silently given
// last-writer-wins instead.  Silently ignoring a precondition is the worst
// possible behavior: the client believes it has protection it does not have.
//
// These checks run before the WebDAV handler, against whatever ETag the
// backend reports, so every backend gets them rather than just pstore.
//
// The evaluation here is inherently racy against a concurrent writer, since
// the stat and the write are not atomic: two "If-None-Match: *" PUTs can both
// find the path absent. It is therefore only the fast path. The parsed
// condition is returned to the caller and threaded down to the backend, and a
// backend that can re-check it inside its commit transaction -- pstore, via
// ConditionalWriteFs, which becomes RequireAbsent / RequireGeneration on the
// write handle -- is what actually delivers the guarantee.
//
// Two forms cannot be expressed at commit and remain best-effort here:
// "If-Match: *" (which asserts existence rather than a particular version) and
// a multi-tag list (which asserts membership). Both are vanishingly rare from
// real clients, and both fail closed on the early check.

package origin_serve

import (
	"context"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/net/webdav"

	"github.com/pelicanplatform/pelican/server_utils"
)

// checkPutPreconditions evaluates If-Match and If-None-Match for a write.
//
// It returns the condition to enforce at commit and true when the request
// should proceed; otherwise it writes the response itself.
func checkPutPreconditions(c *gin.Context, backend server_utils.OriginBackend, relativePath string) (writeCondition, bool) {
	var cond writeCondition

	ifMatch := strings.TrimSpace(c.Request.Header.Get("If-Match"))
	ifNoneMatch := strings.TrimSpace(c.Request.Header.Get("If-None-Match"))
	if ifMatch == "" && ifNoneMatch == "" {
		return cond, true
	}

	ctx := c.Request.Context()
	currentETag, exists, err := currentEntityTag(ctx, backend, relativePath)
	if err != nil {
		// The target cannot be inspected, so the precondition cannot be
		// evaluated. Failing closed is safer than silently ignoring it.
		c.String(http.StatusInternalServerError, "Unable to evaluate precondition: %v", err)
		return cond, false
	}

	// RFC 9110 §13.1.2: If-None-Match: * fails when the target exists; an
	// entity-tag list fails when one of the tags matches. Comparison is weak.
	if ifNoneMatch != "" {
		// "*" must be the sole member of the list. A request that sends it
		// alongside a tag is malformed, and the previous string comparison
		// against "*" sent `*, "junk"` down the entity-tag branch -- where "*"
		// is just a tag that never matches, so the create-only request was
		// silently downgraded to an unconditional overwrite. Any "*" member is
		// therefore treated as the wildcard form, which is the reading that
		// fails closed.
		if etagListHasWildcard(ifNoneMatch) {
			if exists {
				c.String(http.StatusPreconditionFailed, "Object already exists")
				return cond, false
			}
			cond.requireAbsent = true
		} else if exists && etagListMatches(ifNoneMatch, currentETag) {
			c.String(http.StatusPreconditionFailed, "Object matches If-None-Match")
			return cond, false
		}
	}

	// RFC 9110 §13.1.1: If-Match: * fails when the target does not exist; an
	// entity-tag list fails unless one of the tags matches.
	if ifMatch != "" {
		if !exists {
			c.String(http.StatusPreconditionFailed, "Object does not exist")
			return cond, false
		}
		if !etagListHasWildcard(ifMatch) {
			if !etagListMatches(ifMatch, currentETag) {
				c.String(http.StatusPreconditionFailed, "Object does not match If-Match")
				return cond, false
			}
			// A single tag is a compare-and-swap the backend can re-check at
			// commit; a list is a membership test it cannot, and stays with
			// the early check above.
			if tags := splitETagList(ifMatch); len(tags) == 1 {
				cond.requireETag = tags[0]
			}
		}
	}

	return cond, true
}

// currentEntityTag returns the target's current ETag and whether it exists.
//
// It prefers the backend's own tag (webdav.ETager, which pstore implements to
// expose an object's generation) and falls back to the same size-and-mtime
// formula the WebDAV handler would use, so the value a client compares against
// is the one it was given.
func currentEntityTag(ctx context.Context, backend server_utils.OriginBackend, relativePath string) (string, bool, error) {
	info, err := backend.FileSystem().Stat(ctx, relativePath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, err
	}

	if tagger, ok := info.(webdav.ETager); ok {
		tag, tagErr := tagger.ETag(ctx)
		if tagErr == nil && tag != "" {
			return tag, true, nil
		}
		// ErrNotImplemented means "use the default", which is not a failure.
	}
	return computeETag(info), true, nil
}

// splitETagList splits a comma-separated entity-tag list, dropping empties.
func splitETagList(list string) []string {
	parts := strings.Split(list, ",")
	tags := make([]string, 0, len(parts))
	for _, entry := range parts {
		if entry = strings.TrimSpace(entry); entry != "" {
			tags = append(tags, entry)
		}
	}
	return tags
}

// etagListHasWildcard reports whether "*" appears anywhere in an entity-tag
// list.
//
// RFC 9110 §13.1.1 and §13.1.2 define "*" as the whole field value rather than
// a list member, so a list that contains it is malformed. Honoring it as the
// wildcard is the conservative reading: the alternative is comparing it as an
// opaque tag, where it matches nothing and the precondition silently passes.
func etagListHasWildcard(list string) bool {
	for _, tag := range splitETagList(list) {
		if tag == "*" {
			return true
		}
	}
	return false
}

// etagListMatches reports whether candidate appears in a comma-separated
// entity-tag list.
//
// Comparison is weak (RFC 9110 §8.8.3.2): a W/ prefix is ignored on both
// sides, which is what If-None-Match requires and is the safer reading for
// If-Match given that a backend may legitimately report a weak tag.
func etagListMatches(list, candidate string) bool {
	if candidate == "" {
		return false
	}
	want := normalizeETag(candidate)
	for _, entry := range strings.Split(list, ",") {
		if normalizeETag(strings.TrimSpace(entry)) == want {
			return true
		}
	}
	return false
}

// normalizeETag strips a weak-comparison prefix so two tags can be compared.
func normalizeETag(tag string) string {
	return strings.TrimPrefix(strings.TrimSpace(tag), "W/")
}
