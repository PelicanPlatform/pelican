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
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// HTTP semantic-convention attribute keys.  They are written out here rather
// than taken from a semconv package so that exactly these, and nothing else,
// are recorded.
const (
	keyHTTPRequestMethod      = attribute.Key("http.request.method")
	keyHTTPResponseStatusCode = attribute.Key("http.response.status_code")
	keyURLFull                = attribute.Key("url.full")
	keyURLPath                = attribute.Key("url.path")
	keyURLScheme              = attribute.Key("url.scheme")
	keyServerAddress          = attribute.Key("server.address")
	keyServerPort             = attribute.Key("server.port")
	keyUserAgentOriginal      = attribute.Key("user_agent.original")
)

// StartServer extracts trace context from r's headers and starts a
// server-kind span for svc.  It returns r with the span in its context.
//
// The span records the method, path (never the query string), scheme, host
// and user agent; no other header is read.  When tracing is disabled r is
// returned unchanged with a no-op span.
func StartServer(r *http.Request, svc Service, name string) (*http.Request, trace.Span) {
	st := current.Load()
	if st == nil {
		return r, noopSpan
	}
	ctx := st.propagator.Extract(r.Context(), propagation.HeaderCarrier(r.Header))

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	attrs := []attribute.KeyValue{
		keyHTTPRequestMethod.String(r.Method),
		keyURLScheme.String(scheme),
	}
	if r.URL != nil {
		attrs = append(attrs, keyURLPath.String(r.URL.Path))
	}
	if host, port := splitHostPort(r.Host); host != "" {
		attrs = append(attrs, keyServerAddress.String(host))
		if port > 0 {
			attrs = append(attrs, keyServerPort.Int(port))
		}
	}
	if ua := r.UserAgent(); ua != "" {
		attrs = append(attrs, keyUserAgentOriginal.String(ua))
	}

	ctx, span := st.tracer(svc).Start(ctx, name,
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(attrs...))
	return r.WithContext(ctx), span
}

// IsDownloadMethod reports whether an HTTP method is part of an object
// download, which is all that is traced: GET, and the HEAD requests that
// accompany it.
func IsDownloadMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}

// EndServer records the response status on a server span and ends it.  A
// status of 500 or above marks the span failed; a 4xx is the client's error
// and does not.
//
// The status code alone decides whether a server span failed.  To attach the
// error behind a response, use NoteError, which leaves the span status alone.
//
// A statusCode of 0 means the status is not known (a response writer that
// cannot report it): nothing is recorded and the span is not marked failed.
func EndServer(span trace.Span, statusCode int) {
	if span.IsRecording() && statusCode > 0 {
		span.SetAttributes(keyHTTPResponseStatusCode.Int(statusCode))
		if statusCode >= 500 {
			span.SetStatus(codes.Error, http.StatusText(statusCode))
		}
	}
	span.End()
}

// StatusReporter is a response writer that can say which status it sent, as
// gin's ResponseWriter can.
type StatusReporter interface {
	Status() int
}

// EndServerDeferred ends a server span from a defer statement, so that the
// span is ended and exported on every way out of a handler:
//
//	defer tracing.EndServerDeferred(span, c.Writer)
//
// On a normal return it is EndServer(span, w.Status()).  If the handler is
// panicking, the status the writer reports is not what the client will get,
// so the span is ended as a failed 500 and the panic continues with its
// original value.  A 500 is what the server's recovery middleware sends when
// nothing has been written yet; where there is no such middleware, or the
// headers have already gone out, the client sees a dropped connection or a
// truncated response instead, and the span still says 500.
//
// The re-panic adds this function's frames to the top of the stack that a
// recovery middleware logs; the original panic site is still in it.
//
// It must be the deferred function itself, not called from one.  For a span
// that is not being traced it returns at once and a panic is left untouched.
func EndServerDeferred(span trace.Span, w StatusReporter) {
	if !span.SpanContext().IsValid() {
		return
	}
	if r := recover(); r != nil {
		EndServer(span, http.StatusInternalServerError)
		panic(r)
	}
	EndServer(span, w.Status())
}

// Client returns an *http.Client that records a client span for each request
// and injects traceparent.  It returns c itself when tracing is disabled.
//
// The returned client is a shallow copy of c with a wrapped Transport; its
// CheckRedirect, Jar and Timeout are c's.  The wrapped Transport is no longer
// an *http.Transport, so apply Client last, after anything that clones or
// type-asserts the transport.
func Client(c *http.Client) *http.Client {
	if c == nil || !Enabled() {
		return c
	}
	wrapped := *c
	base := c.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	wrapped.Transport = Transport(base)
	return &wrapped
}

// Transport wraps rt so that each request whose context holds a span gets a
// client span and a traceparent header.  It returns rt itself when tracing is
// disabled.  A nil rt means http.DefaultTransport.
//
// A request whose context holds no span is passed to rt untouched: a wrapped
// transport never starts a trace on its own.
func Transport(rt http.RoundTripper) http.RoundTripper {
	if !Enabled() {
		return rt
	}
	if _, ok := rt.(*roundTripper); ok {
		return rt
	}
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &roundTripper{base: rt}
}

type roundTripper struct {
	base http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (t *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	st := current.Load()
	if st == nil || !trace.SpanContextFromContext(req.Context()).IsValid() {
		return t.base.RoundTrip(req)
	}

	attrs := []attribute.KeyValue{
		keyHTTPRequestMethod.String(req.Method),
	}
	if req.URL != nil {
		attrs = append(attrs, keyURLFull.String(redactURL(req.URL)))
		if host := req.URL.Hostname(); host != "" {
			attrs = append(attrs, keyServerAddress.String(host))
		}
		if port := urlPort(req.URL); port > 0 {
			attrs = append(attrs, keyServerPort.Int(port))
		}
	}
	ctx, span := Start(req.Context(), req.Method,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attrs...))

	// A RoundTripper must not modify its input, so the header goes on a clone.
	outReq := req.Clone(ctx)
	st.propagator.Inject(ctx, propagation.HeaderCarrier(outReq.Header))

	resp, err := t.base.RoundTrip(outReq)
	if err != nil {
		RecordError(span, err)
		span.End()
		return resp, err
	}

	span.SetAttributes(keyHTTPResponseStatusCode.Int(resp.StatusCode))
	if resp.StatusCode >= 400 {
		span.SetStatus(codes.Error, http.StatusText(resp.StatusCode))
	}
	// A response that carries no body has nothing left to wait for.  Over
	// HTTP/2 such a response's Body is not http.NoBody, so check the cases
	// that define an empty body as well.
	if resp.Body == nil || resp.Body == http.NoBody || req.Method == http.MethodHead ||
		resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		span.End()
		return resp, nil
	}
	resp.Body = wrapBody(resp.Body, span)
	return resp, nil
}

// CloseIdleConnections forwards to the base transport so that
// http.Client.CloseIdleConnections keeps working on a wrapped client.
func (t *roundTripper) CloseIdleConnections() {
	type closeIdler interface{ CloseIdleConnections() }
	if ci, ok := t.base.(closeIdler); ok {
		ci.CloseIdleConnections()
	}
}

// tracedBody ends the client span when the body is closed, fully read or
// fails, whichever comes first.
type tracedBody struct {
	rc   io.ReadCloser
	span trace.Span
	once sync.Once
}

// tracedReadWriteBody keeps the io.Writer of a body that has one (the body of
// a 101 Switching Protocols response).
type tracedReadWriteBody struct {
	*tracedBody
	w io.Writer
}

func (b tracedReadWriteBody) Write(p []byte) (int, error) {
	return b.w.Write(p)
}

func wrapBody(rc io.ReadCloser, span trace.Span) io.ReadCloser {
	tb := &tracedBody{rc: rc, span: span}
	if w, ok := rc.(io.Writer); ok {
		return tracedReadWriteBody{tracedBody: tb, w: w}
	}
	return tb
}

func (b *tracedBody) end(err error) {
	b.once.Do(func() {
		if err != nil && err != io.EOF {
			RecordError(b.span, err)
		}
		b.span.End()
	})
}

func (b *tracedBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if err != nil {
		b.end(err)
	}
	return n, err
}

func (b *tracedBody) Close() error {
	err := b.rc.Close()
	b.end(nil)
	return err
}

// redactURL returns u without its query string, fragment and user info.
func redactURL(u *url.URL) string {
	clean := *u
	clean.User = nil
	clean.RawQuery = ""
	clean.ForceQuery = false
	clean.Fragment = ""
	clean.RawFragment = ""
	return clean.String()
}

// urlPort returns u's port, or the scheme's default port.
func urlPort(u *url.URL) int {
	if p := u.Port(); p != "" {
		port, err := strconv.Atoi(p)
		if err == nil {
			return port
		}
		return 0
	}
	switch u.Scheme {
	case "https":
		return 443
	case "http":
		return 80
	}
	return 0
}

// splitHostPort splits a Host header value; port is 0 when absent.
func splitHostPort(hostport string) (host string, port int) {
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport, 0
	}
	port, _ = strconv.Atoi(p)
	return h, port
}
