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

// The logging namespace: HTTP access to this server's own logs.
//
// A server that opts in registers /pelican/logging/{sitename} and serves log
// entries under it as virtual objects -- time windows assembled on demand
// rather than files on disk.  That makes logs reachable with the same client,
// the same tokens, and the same authorization model as data, instead of
// requiring shell access to the host.
//
// This is not WebDAV.  There is no directory tree to walk: the log is one
// rolling file, and the paths beneath the namespace are a naming scheme for
// slices of it.  A single catch-all route with its own parser fits that, and
// leaves room to name slices differently later (by job UUID, say) without
// touching the routing table.
//
// Enabling this makes the log file readable by anyone the namespace's tokens
// authorize.  Whatever the server writes to its log, it now hands out; that is
// a property of the feature rather than a flaw in it, but it means log hygiene
// becomes an access-control concern for anyone who turns this on.

package log_exports

import (
	"context"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// loggingNamespaceRoot is the federation prefix all logging namespaces live
// under.  It is deliberately not configurable: clients, the Registry's
// auto-approval rules, and the Director's routing all have to agree on it.
const loggingNamespaceRoot = "/pelican/logging"

// logWindowDuration is the width of one addressable window.
const logWindowDuration = time.Hour

// logSettleMargin is how long after an hour ends before that hour is served.
//
// A closed hour is not the same as a complete one.  The async writer holds
// entries until a size threshold or Logging.Rotation.FlushInterval (50ms by
// default) pushes them out, so at the instant an hour ends some of its last
// entries are still in memory.  Serving the hour then would hand out a copy
// missing its tail -- and, because a closed window is advertised as immutable,
// a cache would keep that truncated copy for good: Cache-Control governs
// whether a response is stored, not whether a stored one is discarded.
//
// Waiting is the whole fix.  Five minutes is enormous next to a 50ms flush and
// costs only freshness, which this endpoint is not the tool for anyway --
// recent lines are what the in-memory buffer behind /api/v1.0/logs/tail is
// for.
const logSettleMargin = 5 * time.Minute

// maxConcurrentLogReads bounds how many log queries run at once.
//
// Each one can walk a large file, so this is the difference between a slow
// endpoint and a server that stops serving data because something is
// polling its logs.  Full rate limiting belongs to infrastructure these
// servers do not have yet; until then a small semaphore is the honest tool.
const maxConcurrentLogReads = 4

// immutableCacheMaxAge is how long a closed, fully-covered window may be
// cached.  A closed hour never changes, so this only needs to be long enough
// to be worth having.
const immutableCacheMaxAge = 24 * time.Hour

// Sentinel errors from parseLogSelector.
//
// These are distinguishable on purpose.  "I do not recognise this kind of
// request" and "this is the kind of request I know, spelled wrongly" are
// different answers, and keeping them apart is what lets a future selector
// kind be added without the error text for today's typos changing meaning.
var (
	errUnknownSelectorKind = errors.New("unrecognized logging object path")
	errMalformedWindow     = errors.New("malformed time window in logging object path")
)

// loggingHandler holds everything a request needs, resolved once at startup.
type loggingHandler struct {
	// sitename is this server's own name, as it appears in the namespace.
	sitename string

	// scope is the resource scope a caller's token must cover.
	scope token_scopes.ResourceScope

	source logSource

	// now is injected so that the settle-margin refusal and cache-directive
	// selection are testable without depending on the wall clock.
	now func() time.Time

	// sem bounds concurrent reads.  Buffered channel rather than a
	// semaphore type to match how the rest of the codebase does this.
	sem chan struct{}

	// authorize decides whether a request may read these logs, writing its own
	// refusal when the answer is no.  It is a field rather than a method call
	// so that tests can exercise everything around it -- path parsing, cache
	// directives, streaming -- without standing up an issuer and minting
	// tokens for each case.
	authorize func(*gin.Context) bool
}

// LoggingNamespaceForSitename returns the federation prefix a server's logs
// are published under.
func LoggingNamespaceForSitename(sitename string) string {
	return path.Join(loggingNamespaceRoot, sitename)
}

// RegisterLoggingExportAPI mounts the logging namespace routes, if this server
// is configured to export its logs.
//
// Registering nothing when the feature is off is deliberate: a server that
// has not opted in should answer 404, which tells an operator plainly that
// this server has no such interface, rather than mounting a route whose only
// possible answer is a refusal.
//
// Middleware is variadic and supplied by the caller: this package serves any
// server type, so anything server-specific -- the web layer's standard
// headers, a server type's HTTP metrics accounting -- is the launcher's to
// choose and thread in, which also keeps this package from importing the web
// layer.  Note that authorization is NOT among them -- it happens inside the
// handler, because the check is against this namespace's scope and the token
// may arrive as a query parameter rather than a header.
func RegisterLoggingExportAPI(ctx context.Context, engine *gin.Engine, serverType server_structs.ServerType, middleware ...gin.HandlerFunc) error {
	if !param.Logging_LogExports_Enabled.GetBool() {
		return nil
	}

	metadata, err := server_utils.GetServerMetadata(ctx, serverType)
	if err != nil {
		return errors.Wrapf(err, "unable to determine this server's name, which %s requires",
			param.Logging_LogExports_Enabled.GetName())
	}

	return registerLoggingExportFor(engine, metadata.Name, middleware...)
}

// registerLoggingExportFor does the work of RegisterLoggingExportAPI once the
// server's own name is known.
//
// Split at the name lookup because that is the one step needing a registry:
// everything after it -- name validation, the route collision guard,
// mounting -- is decidable from local state, and is where a mistake actually
// costs something.  Keeping it reachable without a federation means it can be
// tested.
func registerLoggingExportFor(engine *gin.Engine, sitename string, middleware ...gin.HandlerFunc) error {

	// The sitename becomes a URL path segment, the value compared against the
	// decoded :sitename parameter, and part of a token scope.  Nothing else in
	// Pelican constrains it -- Xrootd.Sitename is documented as human-readable
	// and flows into registry prefixes verbatim -- so a name that cannot
	// survive that round trip has to be caught here.  Refusing at startup is
	// kinder than mounting a route nobody can address.
	if err := validateSitenameForURL(sitename); err != nil {
		return errors.Wrapf(err, "cannot export logs for server name %q", sitename)
	}

	// The WebDAV handlers mount a catch-all at each export's federation
	// prefix.  An export at /pelican or above would own this route's subtree,
	// and registering a static child under an existing catch-all panics Gin as
	// the server comes up.  A federation prefix of / is already refused during
	// configuration for the same reason; this covers the narrower collision.
	if err := checkLoggingPrefixCollision(); err != nil {
		return err
	}

	handler := &loggingHandler{
		sitename: sitename,
		scope: token_scopes.NewResourceScope(
			token_scopes.Wlcg_Storage_Read, LoggingNamespaceForSitename(sitename)),
		source: &activeFileSource{path: param.Logging_LogLocation.GetString()},
		now:    time.Now,
		sem:    make(chan struct{}, maxConcurrentLogReads),
	}
	handler.authorize = handler.verifyToken

	registerLoggingRoutes(engine, handler, middleware...)

	log.Infof("Exporting this server's logs at %s", LoggingNamespaceForSitename(sitename))
	return nil
}

// registerLoggingRoutes mounts the routes for an already-built handler.
//
// Split out from RegisterLoggingExportAPI so tests can supply a sitename and a
// log source directly, without a registry to ask or a real log file to read.
func registerLoggingRoutes(engine *gin.Engine, handler *loggingHandler, middleware ...gin.HandlerFunc) {
	group := engine.Group(loggingNamespaceRoot+"/:sitename", middleware...)

	// HEAD is not a courtesy here.  The Director stats a server before
	// redirecting to it (Director.CheckOriginPresence and
	// Director.CheckCachePresence, both on by default), and it stats with
	// HEAD.  Without this route that stat draws a 405, the server looks
	// absent, and it is dropped from routing entirely.
	group.GET("/*object", handler.serve)
	group.HEAD("/*object", handler.serve)
}

// validateSitenameForURL rejects names that cannot be used as a single path
// segment.
func validateSitenameForURL(sitename string) error {
	if sitename == "" {
		return errors.New("server name is empty")
	}
	// A name that changes when it makes the round trip through a URL cannot be
	// compared against the value arriving in a request.
	if url.PathEscape(sitename) != sitename {
		return errors.Errorf("server name is not usable as a URL path segment; "+
			"set %s to a name made up of unreserved URL characters",
			param.Xrootd_Sitename.GetName())
	}
	// PathEscape leaves these alone, but each would change how the path parses.
	if strings.ContainsAny(sitename, "/?#") || sitename == "." || sitename == ".." {
		return errors.Errorf("server name may not contain '/', '?' or '#', or be '.' or '..'; "+
			"set %s to a simple name", param.Xrootd_Sitename.GetName())
	}
	return nil
}

// prefixShadowsLoggingRoute reports whether mounting the logging routes
// alongside a WebDAV export at federationPrefix would panic Gin as the server
// comes up.
//
// An export mounts a catch-all at its own prefix.  Gin refuses to register a
// route that descends *through* an existing catch-all, so the collision is
// exactly the case where the export sits at or above /pelican/logging -- its
// catch-all then owns the path this route needs to reach.
//
// An export at or below /pelican/logging/<something> does not collide: a
// static segment and a :param segment coexist happily at the same level, so
// only the ancestor case is a problem.  Rejecting more than this would refuse
// configurations that work.
func prefixShadowsLoggingRoute(federationPrefix string) bool {
	prefix := path.Clean("/" + federationPrefix)
	if prefix == "/" || prefix == loggingNamespaceRoot {
		return true
	}
	return strings.HasPrefix(loggingNamespaceRoot+"/", prefix+"/")
}

// checkLoggingPrefixCollision refuses to mount when an export would shadow the
// logging namespace's route.
func checkLoggingPrefixCollision() error {
	exports, err := server_utils.GetOriginExports()
	if err != nil {
		// Not being able to read the exports is not this feature's failure to
		// report; whatever asked for them will have surfaced it already.
		// Skipping the guard is safe for the same reason: if the exports could
		// not be loaded here, the WebDAV handlers could not have mounted their
		// catch-alls from them either, so there is nothing to collide with.
		return nil
	}
	for _, export := range exports {
		if prefixShadowsLoggingRoute(export.FederationPrefix) {
			return errors.Errorf(
				"cannot export logs: the export at %s would shadow the %s route and panic the web server at startup; "+
					"either change that export's federation prefix or disable %s",
				export.FederationPrefix, loggingNamespaceRoot,
				param.Logging_LogExports_Enabled.GetName())
		}
	}
	return nil
}

// refuseLogRequest answers a request without serving a window, and marks the
// refusal uncacheable.
//
// The marking is load-bearing on the 404s: RFC 9111 makes 404 heuristically
// cacheable even with no Cache-Control at all, so an unmarked "not available
// yet" minted during the settle margin could be stored by a cache on the path
// and go on being served long after the window became available.  The other
// statuses do not strictly need it, but a refusal is never a durable answer
// here, and one rule is easier to keep than five.
func refuseLogRequest(c *gin.Context, status int, msg string) {
	c.Header("Cache-Control", "no-store")
	c.JSON(status, server_structs.SimpleApiResp{
		Status: server_structs.RespFailed,
		Msg:    msg,
	})
}

// serve answers a request for one window of this server's logs.
func (h *loggingHandler) serve(c *gin.Context) {
	// The namespace is per-server, so a request naming a different server
	// reached the wrong host.  Answering it would be answering for someone
	// else's logs.
	if c.Param("sitename") != h.sitename {
		refuseLogRequest(c, http.StatusForbidden,
			"this server does not serve logs for the requested server name")
		return
	}

	// Authorize before interpreting the request, so an unauthenticated caller
	// learns nothing about which paths parse or which windows exist.
	if !h.authorize(c) {
		return
	}

	selector, err := parseLogSelector(c.Param("object"), h.now)
	if err != nil {
		refuseLogRequest(c, http.StatusBadRequest, err.Error())
		return
	}

	// An hour that has not finished and settled is not a servable object yet.
	// Refusing is what keeps every response immutable: there is no such thing
	// here as a window whose contents can still change, so nothing has to be
	// kept away from caches.
	_, windowEnd := selector.Bounds()
	if !h.windowSettled(windowEnd) {
		available := windowEnd.Add(logSettleMargin).UTC().Format(time.RFC3339)
		refuseLogRequest(c, http.StatusNotFound,
			"that hour is not available yet; logs are served once an hour has ended and its "+
				"entries have reached disk, which for this window is "+available+
				". For recent activity use the server's log viewer or /api/v1.0/logs/tail")
		return
	}

	// One open serves the whole request.  Coverage and the streamed body must
	// describe the same bytes: with separate opens, a rotation between them
	// could let the coverage check vouch for an hour and the read then stream
	// the fresh, nearly-empty replacement file -- an empty answer under an
	// immutable header, which a cache would keep for good.
	reader, err := h.source.Open(c.Request.Context())
	if err != nil {
		log.WithError(err).Warning("Unable to open the server log for export")
		refuseLogRequest(c, http.StatusInternalServerError, "unable to read the server log")
		return
	}
	defer func() {
		if err := reader.Close(); err != nil {
			log.WithError(err).Debug("Failed to close the log reader after an export request")
		}
	}()

	// Cacheability needs answering before any bytes go out, since it decides a
	// header.  Coverage is the cheap half of it: reading the oldest entry the
	// file still holds.
	oldest, covered, err := reader.Coverage(c.Request.Context())
	if err != nil {
		log.WithError(err).Warning("Unable to determine log file coverage")
		refuseLogRequest(c, http.StatusInternalServerError, "unable to read the server log")
		return
	}

	start, _ := selector.Bounds()
	h.setCacheHeaders(c, selector, oldest, covered, start)
	c.Header("Content-Type", "text/plain; charset=utf-8")

	// A HEAD asks whether this object is servable, not for its contents.
	// Answering it without reading the window keeps the Director's presence
	// check from costing a file scan.  Responses stream, so there is no
	// Content-Length to report either way.
	if c.Request.Method == http.MethodHead {
		c.Status(http.StatusOK)
		return
	}

	select {
	case h.sem <- struct{}{}:
		defer func() { <-h.sem }()
	default:
		c.Header("Retry-After", strconv.Itoa(int(time.Minute.Seconds())))
		refuseLogRequest(c, http.StatusServiceUnavailable,
			"too many concurrent log queries; retry shortly")
		return
	}

	c.Status(http.StatusOK)
	if err := reader.Read(c.Request.Context(), selector, c.Writer); err != nil {
		// The status line is already out, so this cannot become a 500 -- but it
		// must not become a clean 200 either.  The client going away is the
		// one harmless case: nothing downstream will store what nobody
		// received.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			log.WithError(err).Debug("Log export stream ended early; the client went away")
			return
		}
		// Anything else means the body is truncated.  Returning normally would
		// let the server finish the response framing, making the truncation
		// invisible -- and the headers already sent may say immutable, so a
		// cache would keep the short copy forever.  Kill the connection
		// instead, so what went out is visibly incomplete.
		log.WithError(err).Warning("Failed while streaming a log export; aborting the connection " +
			"so the truncated response cannot be mistaken for the whole window")
		abortResponse(c)
	}
}

// abortResponse closes the client's connection without finishing the response,
// so a body cut short by a server-side failure arrives visibly incomplete
// rather than as a well-formed short answer.
//
// Hijacking the connection is best-effort.  HTTP/2 offers no hijacking, and
// gin's writer panics rather than erroring when the underlying writer cannot
// hijack, so the recover turns "cannot abort" into "nothing more to be done"
// -- the failure is already logged either way.  The standard tool for this,
// panic(http.ErrAbortHandler), is not available here: the engine-wide
// gin.Recovery() swallows every panic and then lets the response finish
// normally, which is exactly the clean framing this function exists to avoid.
func abortResponse(c *gin.Context) {
	defer func() {
		_ = recover()
	}()
	if conn, _, err := c.Writer.Hijack(); err == nil {
		_ = conn.Close()
	}
}

// windowSettled reports whether a window has both ended and had time for its
// entries to be flushed to disk.
func (h *loggingHandler) windowSettled(end time.Time) bool {
	return !end.Add(logSettleMargin).After(h.now())
}

// verifyToken checks that the caller holds a token covering this server's
// logging namespace, writing the refusal itself if not.
//
// This is two steps rather than one because token.Verify's own scope check
// compares scope strings exactly.  A federation administrator holding
// storage.read:/ legitimately covers every logging namespace in the
// federation, and an exact comparison would turn that into a refusal.  So the
// first step establishes that the token is real and from an issuer we accept,
// and the second asks the hierarchical question the scopes were designed for.
func (h *loggingHandler) verifyToken(c *gin.Context) bool {
	authOption := token.AuthOption{
		// Authz matters as much as Header: the Director hands the token to the
		// server by appending ?authz= to the redirect, because an HTTP
		// redirect drops the Authorization header on the way.
		Sources: []token.TokenSource{token.Authz, token.Header},
		Issuers: []token.TokenIssuer{token.LocalIssuer},
		// Left empty on purpose -- see the scope check below.
		Scopes: []token_scopes.TokenScope{},
	}
	if param.Logging_LogExports_AllowFederationAdmin.GetBool() {
		authOption.Issuers = append(authOption.Issuers, token.FederationIssuer)
	}

	result, status, ok, err := token.VerifyAndExtract(c, authOption)
	if !ok {
		if err != nil {
			log.WithError(err).Debug("Rejected a log export request during token verification")
		}
		refuseLogRequest(c, status, "authorization is required to read this server's logs")
		return false
	}

	if result == nil || result.Token == nil {
		// Verification passed but produced no parsed token, so the scope
		// question cannot be answered.  Refusing is the only safe reading.
		log.Error("Token verification succeeded without yielding a parsed token; refusing log export")
		refuseLogRequest(c, http.StatusForbidden, "authorization could not be evaluated")
		return false
	}

	if h.scopeAuthorized(result.Token) {
		return true
	}

	refuseLogRequest(c, http.StatusForbidden, "the provided token does not grant "+h.scope.String())
	return false
}

// scopeAuthorized reports whether any scope the token carries covers this
// server's logging namespace.
//
// Hierarchical rather than exact, which is the entire reason this is not left
// to token.Verify: a federation administrator holding storage.read:/ covers
// every logging namespace in the federation, and comparing scope strings for
// equality would refuse precisely the caller AllowFederationAdmin exists to
// admit.
//
// Separated from verifyToken so the decision can be tested against real
// tokens without an issuer, a signature, or an HTTP request -- the surrounding
// verification is token.Verify's business and has its own tests.
func (h *loggingHandler) scopeAuthorized(tok jwt.Token) bool {
	if tok == nil {
		return false
	}
	for _, granted := range token_scopes.ParseResourceScopeString(tok) {
		if granted.Contains(h.scope) {
			return true
		}
	}
	return false
}

// setCacheHeaders states whether the response may be stored.
//
// Two independent things have to hold before it may.  The window must have
// closed, or the bytes are a prefix of an hour still being written.  And the
// log must still reach back far enough to cover it, or the empty response
// produced for a rotated-away hour would be cached as though it were that
// hour's real contents -- and no later response could dislodge it, because
// no-store governs storing rather than evicting.
func (h *loggingHandler) setCacheHeaders(c *gin.Context, sel logSelector, oldest time.Time, covered bool, start time.Time) {
	cacheable := sel.Cacheable() && covered && !oldest.After(start)
	if cacheable {
		c.Header("Cache-Control", "public, max-age="+
			strconv.Itoa(int(immutableCacheMaxAge.Seconds()))+", immutable")
		return
	}
	c.Header("Cache-Control", "no-store")
}

// parseLogSelector turns an object path into the set of entries it names.
//
// One spelling is understood:
//
//	/{year}/{month}/{day}/{hour}[.log]   one hour, addressed in UTC
//
// There is deliberately no way to ask for "the last hour" or for the hour in
// progress.  Every window this endpoint serves has finished and settled, which
// is what lets every response be immutable and cacheable, and removes any need
// to keep some responses away from caches.  Recent lines are a different
// question with a better answer already built: the in-memory buffer behind
// /api/v1.0/logs/tail and the log viewer in the web UI.
//
// The following are fixed, because changing any of them would silently alter
// what an existing URL returns rather than breaking it visibly:
//
//   - Windows are addressed in UTC.  Entries carry their own offset, so
//     matching compares instants and is zone-independent, but the address is
//     UTC so a client and a server in different zones agree on what they are
//     talking about.
//   - The .log suffix is optional and both spellings name the same window.
//   - Segments are fixed-width and zero-padded: /2026/08/20/05, never
//     /2026/8/20/5.  Every accepted spelling of a window is a separate URL --
//     a separate cache key -- for the same bytes, so there is exactly one.
//   - A four-digit numeric first segment means a time window; any other first
//     segment names a kind of selector.  Reserving that split now is what lets
//     a future /job/{uuid} be added without having to tell a UUID from a date
//     by inspection.
func parseLogSelector(object string, now func() time.Time) (logSelector, error) {
	trimmed := strings.Trim(object, "/")
	if trimmed == "" {
		return nil, errors.Wrap(errUnknownSelectorKind, "no log window was named")
	}

	segments := strings.Split(trimmed, "/")
	head := segments[0]

	// A named kind, rather than a date.  None exist yet -- the segment is
	// reserved so one can be added later without having to tell a name from a
	// date by inspection.
	if _, ok := parseFixedDigits(head, 4); !ok {
		return nil, errors.Wrapf(errUnknownSelectorKind,
			"%q is not a kind of log object this server serves", head)
	}

	if len(segments) != 4 {
		return nil, errors.Wrapf(errMalformedWindow,
			"expected {year}/{month}/{day}/{hour}, got %d path segments", len(segments))
	}

	year, _ := parseFixedDigits(segments[0], 4)
	month, ok := parseFixedDigits(segments[1], 2)
	if !ok || month < 1 || month > 12 {
		return nil, errors.Wrap(errMalformedWindow, "month must be two digits, 01-12")
	}
	day, ok := parseFixedDigits(segments[2], 2)
	if !ok || day < 1 || day > 31 {
		return nil, errors.Wrap(errMalformedWindow, "day must be two digits, 01-31")
	}
	hour, ok := parseFixedDigits(strings.TrimSuffix(segments[3], ".log"), 2)
	if !ok || hour > 23 {
		return nil, errors.Wrap(errMalformedWindow, "hour must be two digits, 00-23")
	}

	start := time.Date(year, time.Month(month), day, hour, 0, 0, 0, time.UTC)
	// time.Date normalises out-of-range dates rather than refusing them, so
	// 02/31 would quietly become 03/03.  Comparing back catches that.
	if start.Day() != day || int(start.Month()) != month || start.Year() != year {
		return nil, errors.Wrapf(errMalformedWindow, "%04d-%02d-%02d is not a date", year, month, day)
	}

	return &timeWindowSelector{
		start: start,
		end:   start.Add(logWindowDuration),
		now:   now,
	}, nil
}

// parseFixedDigits parses s as exactly width ASCII digits.
//
// The width is enforced, not just the value: strconv would accept "8", "015",
// and even "+5" where "08", "15" were meant, and each accepted spelling is a
// distinct URL -- hence a distinct cache key downstream -- for the same
// window.  One window, one spelling; the optional .log suffix is the single
// sanctioned exception.
func parseFixedDigits(s string, width int) (int, bool) {
	if len(s) != width {
		return 0, false
	}
	v := 0
	for i := 0; i < width; i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		v = v*10 + int(s[i]-'0')
	}
	return v, true
}
