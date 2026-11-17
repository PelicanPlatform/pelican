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

package origin_serve

import (
	"context"
	"net/http"
	"path"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/tracing"
)

// Span names recorded by the origin.  Only object downloads (GET) and their
// metadata probes (HEAD) are traced; see design/opentelemetry/README.md §8.
const (
	spanServeObject = "origin.serve_object"
	spanAuthorize   = "origin.authorize"
	spanRead        = "origin.read"
)

// Attribute keys used only by the origin.  Keys shared with other services
// live in the tracing package.
const (
	// attrStorageType is the export's configured Origin.StorageType.  It is
	// recorded on origin.serve_object only.
	attrStorageType = attribute.Key("pelican.origin.storage_type")
	// attrAuthorized reports whether authMiddleware let the request through.
	attrAuthorized = attribute.Key("pelican.origin.authorized")
	// attrTokenCount is the number of tokens authorization considered.  A
	// request presenting more than maxTokensPerRequest tokens is treated as
	// presenting none (see extractTokens), so it records 0.  The tokens
	// themselves are never recorded.
	attrTokenCount = attribute.Key("pelican.origin.token_count")
)

// servedObjectPath returns the federation path of the object that
// exportRequestHandler serves for a request routed to the export at
// federationPrefix with the route wildcard wildcardPath.  It is computed the
// way the handler computes the path it opens -- the export's prefix joined
// with the cleaned wildcard -- so that a request such as
// "/a/../b/x" routed to export /a names /a/b/x, the object actually served,
// and never an object under another export.
func servedObjectPath(federationPrefix, wildcardPath string) string {
	return path.Join(federationPrefix, path.Clean(wildcardPath))
}

// isObjectData reports whether a GET response carried object data, whose
// size is recorded as pelican.transfer.bytes.  Error bodies, an empty 304 and
// a HEAD do not count.  The HTML directory listing is also a 200 but, unlike
// every object response (the ETag fast path and the WebDAV handler both set
// one), it carries no ETag, which is what tells the two apart.
func isObjectData(method string, status int, header http.Header) bool {
	if method != http.MethodGet {
		return false
	}
	if status != http.StatusOK && status != http.StatusPartialContent {
		return false
	}
	return header.Get("ETag") != ""
}

// tracingMiddleware starts the origin.serve_object server span for GET and
// HEAD requests on one export.  Every other method, and any request for a
// health-test object, passes straight through without a span.
//
// It must be the first middleware in the export's chain so that every later
// stage sees the span in the request context.  It does not wrap the response
// writer; the status and size are read from gin's writer once the chain has
// run.  When tracing is disabled the request is passed on after a single
// boolean check.
//
// The span is ended by tracing.EndServerDeferred, so a panic further down the
// chain (which the engine's gin.Recovery turns into a 500) still ends and
// exports it, with status 500.
func tracingMiddleware(federationPrefix, storageType string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !tracing.Enabled() || !tracing.IsDownloadMethod(c.Request.Method) {
			c.Next()
			return
		}
		// The route has already matched, so the wildcard is available here.
		objectPath := servedObjectPath(federationPrefix, c.Param("path"))
		if server_utils.IsMonitoringPath(objectPath) {
			c.Next()
			return
		}

		req, span := tracing.StartServer(c.Request, tracing.ServiceOrigin, spanServeObject)
		if span.IsRecording() {
			attrs := []attribute.KeyValue{
				tracing.ObjectPath(objectPath),
				tracing.Namespace(federationPrefix),
				attrStorageType.String(storageType),
			}
			if jobID := c.Request.Header.Get("X-Pelican-JobId"); jobID != "" {
				attrs = append(attrs, tracing.JobID(jobID))
			}
			span.SetAttributes(attrs...)
		}
		c.Request = req

		// Deferred in this order so that the bytes are recorded before the
		// span ends.
		defer tracing.EndServerDeferred(span, c.Writer)
		defer recordObjectBytes(span, c)
		c.Next()
	}
}

// recordObjectBytes records pelican.transfer.bytes on the server span when
// the response carried object data.
func recordObjectBytes(span trace.Span, c *gin.Context) {
	if !span.IsRecording() || !isObjectData(c.Request.Method, c.Writer.Status(), c.Writer.Header()) {
		return
	}
	// gin reports -1 until something is written, which for an object
	// response means an empty object.
	span.SetAttributes(tracing.TransferBytes(int64(max(c.Writer.Size(), 0))))
}

// noteRequestError attaches the error behind a failed response to the
// request's origin.serve_object span.  Whether the span counts as failed is
// decided by the response status alone.
func noteRequestError(c *gin.Context, err error) {
	tracing.NoteError(trace.SpanFromContext(c.Request.Context()), err)
}

// startAuthorize starts the origin.authorize span as a child of the server
// span.  A request without a server span (a method or path that is not
// traced) gets a no-op span, so this never starts a root span.
//
// The returned span must be ended with finishAuthorize.  Its context is not
// returned: authorization runs on the request's own context so that the
// context it produces (and later stages inherit) keeps the server span, not
// this one, as its current span.
func startAuthorize(ctx context.Context) trace.Span {
	_, span := tracing.StartChild(ctx, spanAuthorize)
	return span
}

// finishAuthorize records the outcome on the origin.authorize span and ends
// it.  Calling it again after the span has ended does nothing, so a deferred
// call can cover every early exit while the success path ends the span before
// handing on to the rest of the chain.
func finishAuthorize(span trace.Span, tokenCount int, authorized bool) {
	if span.IsRecording() {
		span.SetAttributes(
			attrAuthorized.Bool(authorized),
			attrTokenCount.Int(tokenCount),
		)
	}
	span.End()
}

// startRead starts the origin.read span for a GET and returns req carrying it
// in its context, so that the WebDAV handler, the backend's OpenFile and any
// upstream request the backend makes become its children.  The new context
// is derived from req's, so every value already on it is kept.
//
// A request without a server span is returned unchanged with a no-op span.
func startRead(req *http.Request) (*http.Request, trace.Span) {
	ctx, span := tracing.StartChild(req.Context(), spanRead)
	if !span.SpanContext().IsValid() {
		return req, span
	}
	return req.WithContext(ctx), span
}
