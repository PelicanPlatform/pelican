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

package local_cache

// Tracing of object GET and HEAD requests served by the persistent cache.
// See design/opentelemetry/README.md, section 7.
//
// Every helper here is a no-op, or a single boolean check, when tracing is
// disabled; the call sites in serveObject, resolveObject and downloadObject
// are one line each.
//
// The cache starts no trace of its own: cache.serve_object continues (or,
// with no traceparent, begins) the trace of the request it serves, and every
// other cache span is started with tracing.StartChild, so it exists only
// under a span already in its context.  Background work -- prestaging,
// fills, health tests -- has none and records nothing.  The embedded client
// likewise starts no trace in a server process, so its spans appear only
// under the cache's.

import (
	"context"
	"net/http"
	"net/url"

	"github.com/pkg/errors"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/tracing"
)

// Span names.
const (
	spanServeObject   = "cache.serve_object"
	spanResolveObject = "cache.resolve_object"
	spanFetchOrigin   = "cache.fetch_origin"
)

// Attribute keys used only by the cache.
const (
	// attrCacheResult is the label serveObject already logs, so that traces
	// and logs agree: hit, miss, pass-through (a response streamed through
	// without being stored) or hit-redirect (a redirect to tier storage).
	attrCacheResult = attribute.Key("pelican.cache.result")
	// attrCacheDecision is what resolveObject decided to do: one of the
	// decision* values below.  It is not the hit-or-miss result: an object
	// whose record exists is "cached" even while its blocks are still being
	// fetched, which attrCacheResult reports as a miss.
	attrCacheDecision = attribute.Key("pelican.cache.decision")
	// attrRangeRequest reports whether the client sent a Range header.
	attrRangeRequest = attribute.Key("pelican.cache.range_request")
	// attrSharedFetch is true on the cache.resolve_object span of a request
	// that joined a whole-object fetch another request had already started.
	attrSharedFetch = attribute.Key("pelican.cache.shared_fetch")
)

// Values of attrCacheDecision.
var (
	decisionCached     = attrCacheDecision.String("cached")
	decisionRevalidate = attrCacheDecision.String("revalidate")
	decisionDownload   = attrCacheDecision.String("download")
	decisionRangeInit  = attrCacheDecision.String("range_init")
	decisionDenied     = attrCacheDecision.String("denied")
)

// startServeSpan starts the cache.serve_object server span for a GET or
// HEAD of an object that is not health-test traffic, and returns r with the
// span in its context.  For anything else, or with tracing disabled, it
// returns r itself and a no-op span.
func startServeSpan(r *http.Request, objectPath, requestId string) (*http.Request, trace.Span) {
	if !tracing.Enabled() || !tracing.IsDownloadMethod(r.Method) || server_utils.IsMonitoringPath(objectPath) {
		return r, tracing.NoopSpan()
	}
	r, span := tracing.StartServer(r, tracing.ServiceCache, spanServeObject)
	if span.IsRecording() {
		attrs := []attribute.KeyValue{
			tracing.ObjectPath(objectPath),
			attrRangeRequest.Bool(r.Header.Get("Range") != ""),
		}
		if requestId != "" {
			attrs = append(attrs, tracing.JobID(requestId))
		}
		span.SetAttributes(attrs...)
	}
	return r, span
}

// statusOf returns w as the reporter of the response status for
// tracing.EndServerDeferred.  The response writer is never wrapped, so the
// status comes from the writer itself when it can say: gin's writer, on the
// TCP routes, has Status.  A plain net/http writer (the unix-socket listener)
// cannot, and its span ends without http.response.status_code and is not
// marked failed, unless the handler panics (see tracing.EndServerDeferred).
//
// The status code alone decides whether the span failed; errors behind a
// response are attached with tracing.NoteError and never mark it failed.
func statusOf(w http.ResponseWriter) tracing.StatusReporter {
	if sr, ok := w.(tracing.StatusReporter); ok {
		return sr
	}
	return unknownStatus{}
}

// unknownStatus reports 0, which tracing.EndServer takes to mean "not known".
type unknownStatus struct{}

func (unknownStatus) Status() int { return 0 }

// noBodyServed is the bytesServed of a response that carried no object data:
// a 304, or a redirect to tier storage.
const noBodyServed = -1

// setServeResult records the cache's result label on the request's span,
// and the object bytes served unless bytesServed is noBodyServed.
func setServeResult(span trace.Span, cacheStatus string, bytesServed int64) {
	if !span.IsRecording() {
		return
	}
	span.SetAttributes(attrCacheResult.String(cacheStatus))
	if bytesServed != noBodyServed {
		span.SetAttributes(tracing.TransferBytes(bytesServed))
	}
}

// setCachedDecision records the decision for an object found whole in the
// cache: served as is, or revalidated with the origin first.  The test is
// the one revalidateObject makes.
func setCachedDecision(span trace.Span, meta *CacheMetadata) {
	if !span.IsRecording() {
		return
	}
	ccDirectives := meta.GetCacheDirectives()
	if ccDirectives.IsStale(meta.LastValidated) {
		span.SetAttributes(decisionRevalidate)
	} else {
		span.SetAttributes(decisionCached)
	}
}

// startFetchSpan starts cache.fetch_origin for a fetch of pelicanURL from the
// origin -- a new whole-object download, or a fill of missing blocks -- as a
// child of the span in ctx; with no span in ctx it returns ctx and a no-op
// span.
func startFetchSpan(ctx context.Context, pelicanURL string) (context.Context, trace.Span) {
	ctx, span := tracing.StartChild(ctx, spanFetchOrigin)
	if span.IsRecording() {
		objectPath := pelicanURL
		if u, err := url.Parse(pelicanURL); err == nil {
			objectPath = u.Path
		}
		span.SetAttributes(tracing.ObjectPath(objectPath))
	}
	return ctx, span
}

// endFetchSpan ends cache.fetch_origin once the download has finished, with
// performErr, the error performDownload returned, or the error the
// download's background completion stored.  A response streamed through
// without being stored (ErrNoStore) is not a failure.
func endFetchSpan(span trace.Span, dl *persistentDownload, performErr error) {
	if !span.IsRecording() {
		span.End()
		return
	}
	err := performErr
	if err == nil || errors.Is(err, ErrNoStore) {
		err = nil
		if stored, ok := dl.completionErr.Load().(error); ok {
			err = stored
		}
	}
	tracing.RecordError(span, err)
	span.End()
}

// startFillSpan starts cache.fetch_origin for a fill of missing blocks that a
// reader of res started, under the span of that reader's request.  The
// returned context is base with the span attached: the fill keeps base's
// lifetime, and the embedded client's spans appear under it.  A fill started
// for a request that is not traced returns base and a no-op span.
func startFillSpan(base context.Context, res *objectResolution) (context.Context, trace.Span) {
	if res.requestSpan == nil || !res.requestSpan.SpanContext().IsValid() {
		return base, tracing.NoopSpan()
	}
	return startFetchSpan(trace.ContextWithSpan(base, res.requestSpan), res.pelicanURL)
}

// endFillSpan ends a fill's cache.fetch_origin span.  A fill that stops early
// has usually only lost its last reader, so the reason is attached without
// marking the span failed.
func endFillSpan(span trace.Span, err error) {
	tracing.NoteError(span, err)
	span.End()
}

// joinFetch marks the span in ctx -- cache.resolve_object -- as having
// joined a whole-object fetch another request started: it gets
// pelican.cache.shared_fetch=true and, when the fetch's span was recorded, a
// link to it.  A fetch whose request was sampled out has a valid span
// context that was never exported, so it is not linked.
func joinFetch(ctx context.Context, fetch trace.SpanContext) {
	span := trace.SpanFromContext(ctx)
	if !span.IsRecording() {
		return
	}
	if fetch.IsSampled() {
		span.AddLink(trace.Link{SpanContext: fetch})
	}
	span.SetAttributes(attrSharedFetch.Bool(true))
}
