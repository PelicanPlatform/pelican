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

// File metadata_multipart.go is the inbound-multipart splitter for
// the V2 origin's "opaque-blob metadata" feature (see the addendum
// in docs/v2-origin-posc-and-metadata.md).
//
// When a client PUTs a multipart/form-data body with the reserved
// part names defined by Origin.Metadata.MetadataPartName /
// ObjectPartName (default "metadata" and "object"), this code:
//
//   1. Reads the metadata part into memory, capped by MaxMetadataBytes.
//   2. Stashes the blob + its content-type on the request context.
//   3. Rewires r.Body to the object part's stream reader so the
//      existing webdav.Handler -> aferoFileSystem -> POSC pipeline
//      streams the object bytes straight through with no buffering.
//   4. Drops Content-Length (it covered the *whole* multipart body,
//      not the object part) and marks the request as chunked.
//
// Any shape violation — wrong ordering, missing required part, an
// unrecognized part name, an oversize metadata part — is reported
// as a 4xx and the request body is closed without any staging-file
// I/O happening.

package origin_serve

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/param"
)

// multipartBlob carries the result of a successful inbound split.
// Its values land verbatim on ObjectCommitEvent.MetadataContentType
// and MetadataBody.
type multipartBlob struct {
	ContentType string
	Body        []byte
}

// multipartBlobCtxKey is a private context key.
type multipartBlobCtxKey struct{}

// withMultipartBlob attaches the parsed blob to ctx so the POSC
// close-hook can pick it up at commit time.
func withMultipartBlob(ctx context.Context, blob *multipartBlob) context.Context {
	if blob == nil {
		return ctx
	}
	return context.WithValue(ctx, multipartBlobCtxKey{}, blob)
}

// multipartBlobFromContext returns the stashed blob, or nil.
func multipartBlobFromContext(ctx context.Context) *multipartBlob {
	if v, ok := ctx.Value(multipartBlobCtxKey{}).(*multipartBlob); ok {
		return v
	}
	return nil
}

// multipartConfig captures the four per-origin tunables that drive
// the splitter. Pulled out into a struct so tests can inject values
// without setting viper globals.
type multipartConfig struct {
	allow            bool
	maxMetadataBytes int64
	metaPartName     string
	objPartName      string
}

// loadMultipartConfig reads the live origin params. Empty / zero
// values fall back to sane defaults so a partially-initialized test
// environment still works.
func loadMultipartConfig() multipartConfig {
	cfg := multipartConfig{
		allow:            param.Origin_Metadata_AllowMultipart.GetBool(),
		maxMetadataBytes: int64(param.Origin_Metadata_MaxMetadataBytes.GetInt()),
		metaPartName:     param.Origin_Metadata_MetadataPartName.GetString(),
		objPartName:      param.Origin_Metadata_ObjectPartName.GetString(),
	}
	if cfg.maxMetadataBytes <= 0 {
		cfg.maxMetadataBytes = 4 * 1024 * 1024
	}
	if cfg.metaPartName == "" {
		cfg.metaPartName = "metadata"
	}
	if cfg.objPartName == "" {
		cfg.objPartName = "object"
	}
	return cfg
}

// isMultipartFormDataPUT reports whether req is a PUT whose
// Content-Type is multipart/form-data. The split logic is reserved
// for PUTs because PROPFIND / MKCOL / etc. do not carry object
// bytes.
func isMultipartFormDataPUT(req *http.Request) bool {
	if req.Method != http.MethodPut {
		return false
	}
	ct := req.Header.Get("Content-Type")
	if ct == "" {
		return false
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mt == "multipart/form-data"
}

// rewriteMultipartPUT inspects req and, when applicable, peels the
// metadata part, stashes it on the returned context, and rewires
// req.Body to the object part. On shape violation it writes a 4xx to
// w and returns ok=false; callers should NOT proceed to the webdav
// handler in that case. When the request is not multipart, returns
// the same req unchanged with ok=true.
//
// IMPORTANT: this is a destructive transform on req. The returned
// request is the one to hand off to webdav.Handler.ServeHTTP.
func rewriteMultipartPUT(w http.ResponseWriter, req *http.Request, cfg multipartConfig) (*http.Request, bool) {
	if !isMultipartFormDataPUT(req) {
		return req, true
	}
	if !cfg.allow {
		http.Error(w, "multipart/form-data uploads are not enabled on this origin", http.StatusUnsupportedMediaType)
		return req, false
	}

	mediaType, params, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/form-data" {
		http.Error(w, "multipart/form-data: malformed Content-Type", http.StatusBadRequest)
		return req, false
	}
	boundary, ok := params["boundary"]
	if !ok || boundary == "" {
		http.Error(w, "multipart/form-data: missing boundary parameter", http.StatusBadRequest)
		return req, false
	}

	mr := multipart.NewReader(req.Body, boundary)
	blob, objPart, splitErr := splitMultipartParts(mr, cfg)
	if splitErr != nil {
		log.Debugf("multipart split: %v", splitErr)
		_ = req.Body.Close()
		http.Error(w, splitErr.userMsg(), splitErr.status())
		return req, false
	}

	// Replace the request body with a streaming reader over the
	// object part. Closing it must also close the original underlying
	// body, so the connection's resources release once webdav is done.
	objReader := &objectPartReadCloser{part: objPart, underlying: req.Body}
	newReq := req.Clone(withMultipartBlob(req.Context(), blob))
	newReq.Body = objReader

	// The original Content-Length was the whole multipart body's
	// length. The webdav handler will derive object-body size from
	// either the Content-Length we set OR the chunked encoding; we
	// have neither (the object part length is unknown without
	// reading it), so unset Content-Length and mark as chunked.
	newReq.Header.Del("Content-Length")
	newReq.ContentLength = -1
	newReq.TransferEncoding = []string{"chunked"}

	// Forward the object part's Content-Type to the webdav layer so
	// downstream HEAD / GET responses can echo it. Mostly cosmetic —
	// the V2 origin doesn't persist Content-Type today — but doing
	// this keeps the request shape sensible if a future MIME-aware
	// backend is plugged in.
	if oct := objPart.Header.Get("Content-Type"); oct != "" {
		newReq.Header.Set("Content-Type", oct)
	} else {
		newReq.Header.Set("Content-Type", "application/octet-stream")
	}
	return newReq, true
}

// objectPartReadCloser bridges the multipart object Part (which only
// implements io.Reader) into an io.ReadCloser whose Close also
// releases the originating request body.
type objectPartReadCloser struct {
	part       *multipart.Part
	underlying io.Closer
}

func (r *objectPartReadCloser) Read(p []byte) (int, error) { return r.part.Read(p) }
func (r *objectPartReadCloser) Close() error {
	closeErr := r.part.Close()
	if underErr := r.underlying.Close(); underErr != nil && closeErr == nil {
		closeErr = underErr
	}
	return closeErr
}

// multipartShapeError carries both a debug-side cause and a
// HTTP-side response status + message. It is the only error type
// rewriteMultipartPUT translates into a 4xx.
type multipartShapeError struct {
	code    int
	message string
	cause   error
}

func (e *multipartShapeError) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("multipart shape: %s (%v)", e.message, e.cause)
	}
	return "multipart shape: " + e.message
}
func (e *multipartShapeError) Unwrap() error   { return e.cause }
func (e *multipartShapeError) status() int     { return e.code }
func (e *multipartShapeError) userMsg() string { return e.message }

// splitMultipartParts reads the first two parts off `mr`. The first
// MUST be `cfg.metaPartName` (read up to cfg.maxMetadataBytes); the
// second MUST be `cfg.objPartName` (returned as a Part the caller
// streams from). Any deviation returns a shape-error mapped to a
// 4xx.
//
// We deliberately do NOT call mr.NextPart() a third time. The
// webdav.Handler will read the object part and then the multipart
// reader will hit EOF when the closing boundary is reached; a stray
// third part is treated as trailing garbage and ignored.
func splitMultipartParts(mr *multipart.Reader, cfg multipartConfig) (*multipartBlob, *multipart.Part, *multipartShapeError) {
	// Part 1: metadata.
	first, err := mr.NextPart()
	if err != nil {
		return nil, nil, &multipartShapeError{
			code:    http.StatusBadRequest,
			message: "multipart body missing the metadata part",
			cause:   err,
		}
	}
	if name := first.FormName(); name != cfg.metaPartName {
		return nil, nil, &multipartShapeError{
			code: http.StatusBadRequest,
			message: fmt.Sprintf(
				"first multipart part must be named %q (got %q); metadata must precede the object body",
				cfg.metaPartName, name),
		}
	}
	body, err := readCapped(first, cfg.maxMetadataBytes)
	cls := first.Close()
	if cls != nil && err == nil {
		err = cls
	}
	if errors.Is(err, errMetadataTooLarge) {
		return nil, nil, &multipartShapeError{
			code:    http.StatusRequestEntityTooLarge,
			message: fmt.Sprintf("metadata part exceeds the %d-byte limit", cfg.maxMetadataBytes),
		}
	}
	if err != nil {
		return nil, nil, &multipartShapeError{
			code:    http.StatusBadRequest,
			message: "metadata part could not be read",
			cause:   err,
		}
	}
	blob := &multipartBlob{
		ContentType: strings.TrimSpace(first.Header.Get("Content-Type")),
		Body:        body,
	}

	// Part 2: object body. Returned to the caller — they own
	// Close() and reading.
	second, err := mr.NextPart()
	if err != nil {
		return nil, nil, &multipartShapeError{
			code:    http.StatusBadRequest,
			message: "multipart body missing the object part after the metadata part",
			cause:   err,
		}
	}
	if name := second.FormName(); name != cfg.objPartName {
		_ = second.Close()
		return nil, nil, &multipartShapeError{
			code: http.StatusBadRequest,
			message: fmt.Sprintf(
				"second multipart part must be named %q (got %q)",
				cfg.objPartName, name),
		}
	}
	return blob, second, nil
}

// errMetadataTooLarge is the sentinel readCapped raises when the
// metadata part exceeds the configured cap. It is translated to a
// 413 by the caller.
var errMetadataTooLarge = errors.New("metadata part exceeds the configured maximum size")

// readCapped reads up to max+1 bytes from r. If exactly max+1 bytes
// arrive it returns errMetadataTooLarge (so a body of exactly max
// bytes is accepted; one byte over is rejected). The peek byte is
// discarded.
func readCapped(r io.Reader, max int64) ([]byte, error) {
	if max <= 0 {
		return nil, errors.New("readCapped: non-positive cap")
	}
	limited := io.LimitReader(r, max+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, errMetadataTooLarge
	}
	return body, nil
}
