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

package director

// Tracing for the director's handling of object download redirects (design
// section 6).  Everything here is a no-op, or a single boolean check, when
// tracing is disabled, and allocates nothing then: every helper that sets
// attributes returns before building them unless its span is recording.
//
// Span tree for one GET or HEAD redirect:
//
//	director.redirect            (server span, redirectToCache / redirectToOrigin)
//	├─ director.match_namespace  (getSortedAds: namespace lookup and filtering)
//	├─ director.stat_servers     (generateAvailabilityMaps, only when a stat is issued)
//	│   └─ HEAD                  (sendHeadReq, through tracing.Client)
//	└─ director.sort_servers     (sortServerAds, once per server type sorted)
//
// Child spans are started with tracing.StartChild, so callers other than the
// redirect handlers (the director UI's stat endpoint, unit tests that call the
// stages directly) never start a trace.
//
// Errors.  A span is marked failed only when the director itself failed.
// The redirect span is a server span: its status comes from the response code
// alone (tracing.EndServer fails it for a 5xx only), and the handlers attach
// the error behind any response to it with tracing.NoteError.  That covers
// every error the stages return, so the child spans do not repeat it; the one
// child that marks itself failed is a sort that errors out, which always ends
// the request in a 500.
//
// The stat pool refreshes a cached result that is about to expire by
// re-running the query in the background with the context of the query that
// found it (see queryServersForObject).  That context is cancelled when the
// triggering query returns, so such a refresh shows up in the trace as a
// cancelled HEAD under a director.stat_servers span that has already ended.
// This is how the refresh has always behaved; tracing only makes it visible.

import (
	"context"
	"encoding/json"
	"math"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/tracing"
	"github.com/pelicanplatform/pelican/utils"
)

// Span and event names.
const (
	spanRedirect       = "director.redirect"
	spanMatchNamespace = "director.match_namespace"
	spanStatServers    = "director.stat_servers"
	spanSortServers    = "director.sort_servers"
	eventDecision      = "director.decision"
)

// Director-specific attribute keys.
const (
	// attrRedirectTarget is "cache" or "origin": the kind of server the
	// client was actually sent to, i.e. the type of the first server in the
	// response.  redirectToCache reports "origin" when it falls back to an
	// origin because no cache can serve the request, and redirectToOrigin
	// reports "cache" when cache chaining places caches ahead of the origins.
	attrRedirectTarget = attribute.Key("pelican.director.redirect_target")
	// attrChosen lists the servers placed in the response (the Link header),
	// in order, as host[:port].
	attrChosen = attribute.Key("pelican.director.chosen")
	// attrCandidateCaches and attrCandidateOrigins count the ads that
	// survived namespace matching and filtering.
	attrCandidateCaches  = attribute.Key("pelican.director.candidates.caches")
	attrCandidateOrigins = attribute.Key("pelican.director.candidates.origins")
	// attrCandidates is the number of ads handed to one sort.
	attrCandidates = attribute.Key("pelican.director.candidates")
	// attrServerType is "origin" or "cache": what one sort is ordering.
	attrServerType = attribute.Key("pelican.director.server_type")
	// attrSortMethod is the sort algorithm actually used, after any fallback.
	attrSortMethod = attribute.Key("pelican.director.sort_method")
	// attrClientCoordinateSource names the branch of getClientCoordinate that
	// located the client.
	attrClientCoordinateSource = attribute.Key("pelican.director.client_coordinate_source")
	// attrStatQueried and attrStatAvailable count the servers a stat asked
	// and the servers that reported having the object.
	attrStatQueried   = attribute.Key("pelican.director.stat.queried")
	attrStatAvailable = attribute.Key("pelican.director.stat.available")
	// attrDecision holds the JSON-encoded RedirectInfo on the decision event.
	attrDecision = attribute.Key("pelican.director.decision")
)

// Values of attrClientCoordinateSource.
const (
	coordSourceHeader       = "header"
	coordSourceOverride     = "override"
	coordSourceCachedRandom = "cached_random"
	coordSourceMaxMind      = "maxmind"
	coordSourceRandom       = "random"
)

// decisionCoordinatePrecision is the number of decimal places the client's
// latitude and longitude keep in the decision event: one place is about
// 11 km, enough to explain a distance sort without locating the client.
const decisionCoordinatePrecision = 10.0

// startRedirectSpan starts the director.redirect server span for a GET or
// HEAD object request and puts it on ginCtx.Request, where it stays for the
// rest of the request.  The request carrying the span is a shallow copy that
// shares URL and Header with the original, so a path rewritten before the
// handler, and the access logger and metrics middleware reading the method and
// path after it, see the same values.
//
// The span is a no-op when tracing is disabled, for other methods, and for the
// director's own health test objects under server_utils.MonitoringBaseNs.
func startRedirectSpan(ginCtx *gin.Context) trace.Span {
	if !tracing.Enabled() || !shouldTraceRedirect(ginCtx) {
		return tracing.NoopSpan()
	}
	req, span := tracing.StartServer(ginCtx.Request, tracing.ServiceDirector, spanRedirect)
	ginCtx.Request = req
	if span.IsRecording() {
		span.SetAttributes(tracing.ObjectPath(getObjectPathFromRequest(ginCtx)))
	}
	return span
}

// shouldTraceRedirect reports whether a redirect request gets a span: only
// object downloads (GET and HEAD), and never the director's health tests.
func shouldTraceRedirect(ginCtx *gin.Context) bool {
	if ginCtx.Request == nil || ginCtx.Request.URL == nil {
		return false
	}
	if !tracing.IsDownloadMethod(ginCtx.Request.Method) {
		return false
	}
	return !server_utils.IsMonitoringPath(getObjectPathFromRequest(ginCtx))
}

// redirectSpan returns the director.redirect span of the request, or a no-op
// span.
func redirectSpan(ginCtx *gin.Context) trace.Span {
	if ginCtx == nil || ginCtx.Request == nil {
		return tracing.NoopSpan()
	}
	return trace.SpanFromContext(ginCtx.Request.Context())
}

// recordRequestID records the request ID the handler uses (and returns in
// X-Pelican-JobId) on the redirect span.
func recordRequestID(span trace.Span, requestId uuid.UUID) {
	if !span.IsRecording() {
		return
	}
	span.SetAttributes(tracing.JobID(requestId.String()))
}

// noteRedirectFailure attaches a failure that the handler describes only by
// its message to the redirect span, without marking the span failed.  The
// error value is built only when the span is recording.
func noteRedirectFailure(span trace.Span, msg string) {
	if !span.IsRecording() {
		return
	}
	tracing.NoteError(span, redirectFailure(msg))
}

// redirectFailure is an error that the director describes only by a message.
type redirectFailure string

func (e redirectFailure) Error() string { return string(e) }

// redirectTarget names the kind of server ad is, as recorded in
// attrRedirectTarget.
func redirectTarget(ad server_structs.ServerAd) string {
	switch ad.Type {
	case server_structs.CacheType.String():
		return "cache"
	case server_structs.OriginType.String():
		return "origin"
	}
	return strings.ToLower(ad.Type)
}

// recordRedirectChoice records where the client is being sent: the kind of
// the first server in the response and the servers listed in the response, in
// the order and number the Link header lists them.
func recordRedirectChoice(span trace.Span, ginCtx *gin.Context, chosen []server_structs.ServerAd, nsAd server_structs.NamespaceAd) {
	if !span.IsRecording() || len(chosen) == 0 {
		return
	}
	n := len(chosen)
	if n > serverResLimit {
		n = serverResLimit
	}
	reqPath := getObjectPathFromRequest(ginCtx)
	hosts := make([]string, 0, n)
	for _, ad := range chosen[:n] {
		redirectURL := getRedirectURL(reqPath, ad, !nsAd.Caps.PublicReads)
		hosts = append(hosts, redirectURL.Host)
	}
	span.SetAttributes(
		attrRedirectTarget.String(redirectTarget(chosen[0])),
		attrChosen.StringSlice(hosts),
		tracing.Namespace(nsAd.Path),
	)
}

// startMatchNamespaceSpan starts director.match_namespace under the request's
// redirect span.
func startMatchNamespaceSpan(ginCtx *gin.Context) trace.Span {
	if ginCtx == nil || ginCtx.Request == nil {
		return tracing.NoopSpan()
	}
	_, span := tracing.StartChild(ginCtx.Request.Context(), spanMatchNamespace)
	return span
}

// recordNamespace sets the matched namespace prefix on the match span and on
// the redirect span.
func recordNamespace(ginCtx *gin.Context, matchSpan trace.Span, ads []copyAd) {
	if !matchSpan.IsRecording() || len(ads) == 0 {
		return
	}
	ns := tracing.Namespace(ads[0].NamespaceAd.Path)
	matchSpan.SetAttributes(ns)
	redirectSpan(ginCtx).SetAttributes(ns)
}

// recordCandidates records how many origins and caches survived matching and
// filtering on the redirect span.
func recordCandidates(ginCtx *gin.Context, origins, caches int) {
	span := redirectSpan(ginCtx)
	if !span.IsRecording() {
		return
	}
	span.SetAttributes(
		attrCandidateOrigins.Int(origins),
		attrCandidateCaches.Int(caches),
	)
}

// startStatSpan starts director.stat_servers under the request's redirect
// span.  It returns a context to hand to the stat query that holds the span
// but carries no deadline or cancellation (see tracing.CarrySpan), so the
// query is cancelled exactly as it was with context.Background().
//
// The span's parent is always the redirect span in ginCtx, whoever calls.
// When the adaptive sort stats caches lazily, from inside sortServerAds, it
// calls generateAvailabilityMaps with only the gin context, so that
// director.stat_servers is a child of director.redirect and a sibling of the
// director.sort_servers span whose time window contains it.
func startStatSpan(ginCtx *gin.Context, queried int) (context.Context, trace.Span) {
	if ginCtx == nil || ginCtx.Request == nil {
		return context.Background(), tracing.NoopSpan()
	}
	ctx, span := tracing.StartChild(ginCtx.Request.Context(), spanStatServers)
	if span.IsRecording() {
		span.SetAttributes(attrStatQueried.Int(queried))
	}
	return tracing.CarrySpan(context.Background(), ctx), span
}

// endStatSpan records how many servers reported the object, and why the
// query failed if it did, and ends the span.  A failed stat does not fail the
// redirect (the director carries on without the availability check), so it is
// noted, not marked as a failure.
func endStatSpan(span trace.Span, qr queryResult) {
	if span.IsRecording() {
		span.SetAttributes(attrStatAvailable.Int(len(qr.Objects)))
		if qr.Status == queryFailed {
			tracing.NoteError(span, redirectFailure(qr.Msg))
		}
	}
	span.End()
}

// startSortSpan starts director.sort_servers under the span in ctx.
func startSortSpan(ctx context.Context, isOriginSort bool, candidates int, method server_structs.SortType) (context.Context, trace.Span) {
	ctx, span := tracing.StartChild(ctx, spanSortServers)
	if !span.IsRecording() {
		return ctx, span
	}
	serverType := "cache"
	if isOriginSort {
		serverType = "origin"
	}
	span.SetAttributes(
		attrServerType.String(serverType),
		attrCandidates.Int(candidates),
		attrSortMethod.String(method.String()),
	)
	return ctx, span
}

// recordSortFallback notes the error that made the configured sort fail and
// replaces the sort method on the sort span with the fallback that produced
// the result.  The sort still succeeded, so the span is not marked failed.
func recordSortFallback(span trace.Span, sortErr error, method server_structs.SortType) {
	if !span.IsRecording() {
		return
	}
	tracing.NoteError(span, sortErr)
	span.SetAttributes(attrSortMethod.String(method.String()))
}

// recordSortError marks the sort span failed with err and returns err
// unchanged.  A sort error always ends the request with a 500, so this is a
// failure of the director's own.
func recordSortError(span trace.Span, err error) error {
	tracing.RecordError(span, err)
	return err
}

// recordCoordinateSource records which branch of getClientCoordinate
// located the client on the span in ctx.
func recordCoordinateSource(ctx context.Context, source string) {
	if ctx == nil {
		return
	}
	span := trace.SpanFromContext(ctx)
	if !span.IsRecording() {
		return
	}
	span.SetAttributes(attrClientCoordinateSource.String(source))
}

// roundCoordinate rounds a latitude or longitude to the precision kept in the
// decision event.
func roundCoordinate(v float64) float64 {
	return math.Round(v*decisionCoordinatePrecision) / decisionCoordinatePrecision
}

// addDecisionEvent adds the director's decision (the RedirectInfo it already
// computes for X-Pelican-Debug) to the redirect span as a director.decision
// event.  Nothing is marshalled unless the span is recording.
//
// The event is built from a copy in which the client IP address is masked the
// way the redirect metrics mask it and the client's coordinate is rounded to
// one decimal place, since a client may send its exact location in
// X-Pelican-Coordinate.  ClientInfo and its Coordinate are value fields, so
// the copy does not alias info, which may still be returned in full to a debug
// client.  ServersInfo is a map shared with info; it is only read here.
func addDecisionEvent(ginCtx *gin.Context, info *server_structs.RedirectInfo) {
	span := redirectSpan(ginCtx)
	if info == nil || !span.IsRecording() {
		return
	}
	masked := *info
	if network, ok := utils.ApplyIPMask(masked.ClientInfo.IpAddr); ok {
		masked.ClientInfo.IpAddr = network
	} else {
		masked.ClientInfo.IpAddr = ""
	}
	masked.ClientInfo.Coordinate.Lat = roundCoordinate(masked.ClientInfo.Coordinate.Lat)
	masked.ClientInfo.Coordinate.Long = roundCoordinate(masked.ClientInfo.Coordinate.Long)
	encoded, err := json.Marshal(&masked)
	if err != nil {
		// The redirect itself is unaffected.
		tracing.NoteError(span, err)
		return
	}
	span.AddEvent(eventDecision, trace.WithAttributes(attrDecision.String(string(encoded))))
}
