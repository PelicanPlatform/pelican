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

package error_codes

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	pkgerrors "github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The sentinels answer "is this that error", and the taxonomy is a hierarchy,
// so a child satisfies its parent but never the reverse.
func TestIsHierarchical(t *testing.T) {
	cause := errors.New("server returned 403 Forbidden")

	tests := []struct {
		name   string
		err    error
		target error
		want   bool
	}{
		{"exact match", NewAuthorizationError(cause), ErrAuthorization, true},
		{"child satisfies parent", NewAuthorization_TokenNotFoundError(cause), ErrAuthorization, true},
		{"parent does not satisfy child", NewAuthorizationError(cause), ErrAuthorization_TokenNotFound, false},
		{"child matches itself", NewAuthorization_TokenNotFoundError(cause), ErrAuthorization_TokenNotFound, true},
		{"different family", NewTransferError(cause), ErrAuthorization, false},
		{"sibling children do not match", NewSpecification_FileNotFoundError(cause), ErrSpecification_FileAlreadyExists, false},
		{"unclassified matches nothing", cause, ErrAuthorization, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, errors.Is(tc.err, tc.target))
		})
	}
}

// The classification is reached through the layers of context that pkg/errors
// adds on the way up, which is the whole reason a bare type assertion was never
// enough at the CLI exit sites.
func TestIsThroughWraps(t *testing.T) {
	classified := NewAuthorizationError(errors.New("server returned 403 Forbidden"))
	wrapped := pkgerrors.Wrap(pkgerrors.Wrap(error(classified), "request failed"), "failed download")

	assert.True(t, errors.Is(wrapped, ErrAuthorization))
	assert.True(t, errors.Is(wrapped, ErrPelican))
	assert.False(t, errors.Is(wrapped, ErrTransfer))
}

// A tree, not just a chain: an accumulator reports every attempt via
// Unwrap() []error, and a definitive answer from any one of them counts.
func TestIsAcrossJoinedTree(t *testing.T) {
	throttled := NewTransfer_CacheOverloadedError(errors.New("429 from cache-a"))
	notFound := NewSpecification_FileNotFoundError(errors.New("404 from origin-b"))
	joined := errors.Join(error(throttled), error(notFound))

	assert.True(t, errors.Is(joined, ErrSpecification_FileNotFound),
		"a not-found recorded behind a throttle must still be found")
	assert.True(t, errors.Is(joined, ErrTransfer_CacheOverloaded))
}

func TestErrPelican(t *testing.T) {
	assert.True(t, errors.Is(NewTransferError(errors.New("boom")), ErrPelican))
	assert.True(t, errors.Is(NewParameter_FileNotFoundError(errors.New("boom")), ErrPelican))
	assert.False(t, errors.Is(errors.New("boom"), ErrPelican),
		"an unclassified error must not look classified")

	// ErrPelican's empty errorType is an implementation detail, not a taxonomy
	// entry, and must never be reachable by the hierarchical rule.
	for _, sentinel := range sentinels {
		assert.NotEmpty(t, sentinel.errorType)
	}
}

// Exactly opts out of hierarchical matching, for the parent codes that carry a
// meaning their children do not share.
func TestExactly(t *testing.T) {
	cause := errors.New("nothing serves this path")

	assert.True(t, errors.Is(NewSpecificationError(cause), Exactly(ErrSpecification)))
	assert.False(t, errors.Is(NewSpecification_FileNotFoundError(cause), Exactly(ErrSpecification)),
		"Exactly must not match a descendant")
	assert.False(t, errors.Is(NewSpecification_FileAlreadyExistsError(cause), Exactly(ErrSpecification)),
		"the write-path members must not read as a bare Specification")

	// Still reached through wrapping.
	wrapped := pkgerrors.Wrap(error(NewSpecificationError(cause)), "failed download")
	assert.True(t, errors.Is(wrapped, Exactly(ErrSpecification)))
}

func TestExitCodeFor(t *testing.T) {
	cause := errors.New("server returned 403 Forbidden")

	code, ok := ExitCodeFor(pkgerrors.Wrap(error(NewAuthorizationError(cause)), "failed download"))
	require.True(t, ok)
	assert.Equal(t, 7, code, "the documented Authorization exit code, not the untyped fallback of 1")

	code, ok = ExitCodeFor(NewSpecification_FileNotFoundError(cause))
	require.True(t, ok)
	assert.Equal(t, 8, code)

	// An unclassified error yields no code. The bool matters: a caller that
	// exited on the int alone would exit 0 here and report success for a
	// failed transfer.
	code, ok = ExitCodeFor(errors.New("boom"))
	assert.False(t, ok)
	assert.Zero(t, code)

	// Every documented exit code is non-zero, which is what makes that
	// failure mode possible to state so plainly.
	for _, sentinel := range sentinels {
		assert.NotZero(t, sentinel.exitCode, sentinel.errorType)
	}
}

// ExitCodeFor reports the narrowest classification that matches, so the table
// it walks has to reach every child before that child's parent.
func TestSentinelsOrderedSpecificFirst(t *testing.T) {
	seen := make(map[string]int, len(sentinels))
	for i, sentinel := range sentinels {
		seen[sentinel.errorType] = i
	}
	require.Len(t, seen, len(sentinels), "duplicate errorType among the sentinels")

	for _, sentinel := range sentinels {
		parent := sentinel.errorType
		for {
			idx := strings.LastIndex(parent, ".")
			if idx < 0 {
				break
			}
			parent = parent[:idx]
			parentPos, ok := seen[parent]
			if !ok {
				continue
			}
			assert.Less(t, seen[sentinel.errorType], parentPos,
				"%s must be tested before its parent %s", sentinel.errorType, parent)
		}
	}
}

func TestMessage(t *testing.T) {
	classified := NewAuthorizationError(errors.New("server returned 403 Forbidden"))
	wrapped := pkgerrors.Wrap(pkgerrors.Wrap(error(classified), "request failed"), "failed download")

	msg, ok := Message(wrapped)
	require.True(t, ok)
	assert.Equal(t, "Authorization Error: Error code 4000: server returned 403 Forbidden", msg)
	assert.NotContains(t, msg, "failed download",
		"the context accumulated on the way up is noise in a user-facing message")

	_, ok = Message(errors.New("boom"))
	assert.False(t, ok)
}

// A sentinel carries no cause, so it must never be mistaken for a usable error
// value. This pins the reason the doc comment tells callers to use the
// constructors instead.
func TestSentinelCarriesNoCause(t *testing.T) {
	assert.Equal(t, "Authorization", ErrAuthorization.Error())
	assert.Nil(t, ErrAuthorization.Unwrap())
	assert.NotEqual(t, fmt.Sprint(ErrAuthorization), fmt.Sprint(NewAuthorizationError(errors.New("boom"))))
}
