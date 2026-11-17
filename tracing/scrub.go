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

package tracing

import (
	"fmt"
	"regexp"

	"github.com/pkg/errors"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const redacted = "REDACTED"

// tokenParams are the names whose values are credentials.
const tokenParams = `authz|access_token|refresh_token|id_token|bearer_token|scitoken|client_secret|token`

var (
	// The credentials of an Authorization header, also URL-encoded:
	// "Bearer <token>", "Bearer%20<token>", "Basic <credentials>".  Whatever
	// follows the scheme is redacted, however short.  That also costs a
	// sentence such as "bearer token expired" one word, which is the right
	// way round: losing a word of prose is harmless, and a short opaque
	// token must not slip through.
	authSchemeRegexp = regexp.MustCompile(`(?i)(\b(?:bearer|basic)(?:\s+|%20))[^\s"'&,;\]]+`)
	// The value of a token-bearing query or form parameter (authz=...).  The
	// name must start the string or follow a separator, so that, for
	// example, "my_token=" is left alone.
	tokenParamRegexp = regexp.MustCompile(
		`(?i)((?:^|[?&;\s"'(,{])(?:` + tokenParams + `)=)[^&\s"';#,)}]*`)
	// The value of a token-bearing JSON member ("access_token": "...").  The
	// name must be quoted: an unquoted "token: ..." is how error messages are
	// written ("failed to get token: no such file"), not how tokens travel.
	jsonTokenRegexp = regexp.MustCompile(
		`(?i)("(?:` + tokenParams + `)"\s*:\s*")[^"]*`)
	// The same parameters inside a URL that was itself URL-encoded, where
	// "=" is %3D and the next "&" is %26.
	encodedTokenParamRegexp = regexp.MustCompile(
		`(?i)((?:` + tokenParams + `)%3D)(?:[^&\s"';#%]|%(?:[013-9a-f][0-9a-f]|2[0-57-9a-f]))*`)
	// Anything shaped like a JWT, wherever it appears.  Pelican's own tokens
	// are JWTs, so this catches them in any position.
	jwtRegexp = regexp.MustCompile(`ey[A-Za-z0-9_-]{8,}\.ey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+`)
)

// Scrub removes credentials from s: Authorization values, token-bearing
// parameters and anything shaped like a JWT.  Each secret is replaced with
// REDACTED.
//
// It is a second line of defence.  The first is that spans never record
// request headers or query strings at all; Scrub covers free text, such as
// error messages, that may quote them.  It matches the shapes credentials
// travel in.  A sentence that merely mentions a token ("failed to get token:
// no such file") is left alone; one that names an Authorization scheme
// ("bearer token expired") loses the word after the scheme.
func Scrub(s string) string {
	s = authSchemeRegexp.ReplaceAllString(s, "${1}"+redacted)
	s = tokenParamRegexp.ReplaceAllString(s, "${1}"+redacted)
	s = jsonTokenRegexp.ReplaceAllString(s, "${1}"+redacted)
	s = encodedTokenParamRegexp.ReplaceAllString(s, "${1}"+redacted)
	s = jwtRegexp.ReplaceAllString(s, redacted)
	return s
}

// RecordError marks the span failed with a scrubbed error message, and notes
// the error on it as NoteError does.  It does nothing for a nil error or a
// span that is not recording.
//
// Do not use it on a server span: there the response status decides whether
// the span failed (see EndServer), and the error is attached with NoteError.
func RecordError(span trace.Span, err error) {
	if err == nil || span == nil || !span.IsRecording() {
		return
	}
	span.SetStatus(codes.Error, Scrub(err.Error()))
	NoteError(span, err)
}

// NoteError attaches err to the span without changing whether the span
// counts as failed: it sets error.type and adds an "exception" event carrying
// the scrubbed message.  The raw error is never recorded.  It does nothing
// for a nil error or a span that is not recording.
func NoteError(span trace.Span, err error) {
	if err == nil || span == nil || !span.IsRecording() {
		return
	}
	// The type of the underlying error, not of a wrapper that only adds a
	// message or a stack.
	errType := fmt.Sprintf("%T", errors.Cause(err))
	span.SetAttributes(attribute.String("error.type", errType))
	span.AddEvent("exception", trace.WithAttributes(
		attribute.String("exception.type", errType),
		attribute.String("exception.message", Scrub(err.Error())),
	))
}
