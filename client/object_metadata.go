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

// File object_metadata.go provides client-side helpers for the
// V2-origin "metadata on close" feature. Users hand the `pelican`
// CLI a JSON file describing custom per-upload metadata; this file
// reads & validates the JSON, then renders it into the RFC 9651
// Structured Fields dictionary that the origin's
// ParseObjectMetadataHeader expects on the wire.

package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/textproto"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dunglas/httpsfv"
	"github.com/pkg/errors"
)

// clientMultipartMetadataPartName and clientMultipartObjectPartName
// are the field names the client sends on a multipart upload. They
// must match the origin's Origin.Metadata.MetadataPartName /
// ObjectPartName (default "metadata" and "object"). An operator who
// reconfigures the server-side names is responsible for fielding a
// matching client.
const (
	clientMultipartMetadataPartName = "metadata"
	clientMultipartObjectPartName   = "object"
)

// buildMultipartUploadBody wraps the per-object `tee` reader as the
// "object" part of a streaming multipart/form-data body. The
// "metadata" part is written first (small, in memory) so a server
// using a one-pass multipart reader can pick up the blob before the
// file bytes start arriving.
//
// Returns the request body io.Reader (suitable for
// http.NewRequestWithContext) and the Content-Type value (including
// the boundary parameter).
func buildMultipartUploadBody(tee io.Reader, blob *objectMetadataBlob) (io.Reader, string) {
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	contentType := mw.FormDataContentType()

	go func() {
		// We close pw on the way out so the reader side sees io.EOF
		// once we're done OR a non-nil error if anything went wrong
		// while writing the multipart structure.
		var writeErr error
		defer func() {
			if writeErr != nil {
				_ = pw.CloseWithError(writeErr)
			} else {
				_ = pw.Close()
			}
		}()

		// Part 1: opaque metadata blob.
		metaHeader := textproto.MIMEHeader{}
		metaHeader.Set("Content-Disposition", fmt.Sprintf(
			`form-data; name=%q`, clientMultipartMetadataPartName))
		ct := strings.TrimSpace(blob.contentType)
		if ct == "" {
			ct = "application/octet-stream"
		}
		metaHeader.Set("Content-Type", ct)
		metaPart, err := mw.CreatePart(metaHeader)
		if err != nil {
			writeErr = errors.Wrap(err, "multipart create metadata part")
			return
		}
		if _, err := metaPart.Write(blob.body); err != nil {
			writeErr = errors.Wrap(err, "multipart write metadata part")
			return
		}

		// Part 2: object body, streamed.
		objHeader := textproto.MIMEHeader{}
		objHeader.Set("Content-Disposition", fmt.Sprintf(
			`form-data; name=%q; filename="object"`, clientMultipartObjectPartName))
		objHeader.Set("Content-Type", "application/octet-stream")
		objPart, err := mw.CreatePart(objHeader)
		if err != nil {
			writeErr = errors.Wrap(err, "multipart create object part")
			return
		}
		if _, err := io.Copy(objPart, tee); err != nil {
			writeErr = errors.Wrap(err, "multipart stream object part")
			return
		}

		if err := mw.Close(); err != nil {
			writeErr = errors.Wrap(err, "multipart close")
			return
		}
	}()

	return pr, contentType
}

// ObjectMetadataHeaderName is the HTTP header that carries the
// rendered Structured Fields dictionary on the upload PUT request.
// Kept as a public constant so other clients can reuse it.
const ObjectMetadataHeaderName = "X-Pelican-Object-Metadata"

// objectMetadataBlob is the in-memory value the
// WithObjectMetadataBlob / WithObjectMetadataBlobFile options
// produce. NewTransferJob's option-apply pass stashes it on the
// TransferJob; uploadObject reads it and switches the PUT body to
// multipart/form-data when present.
type objectMetadataBlob struct {
	body        []byte
	contentType string
}

// loadObjectMetadataBlobFile reads a blob from disk and sniffs the
// Content-Type from the file's extension when no explicit override
// is in play. The Content-Type can be overridden later by
// WithObjectMetadataContentType (the option-apply switch handles
// the override).
func loadObjectMetadataBlobFile(path string) (*objectMetadataBlob, error) {
	if path == "" {
		return nil, errors.New("metadata blob file path is empty")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Wrapf(err, "reading metadata blob file %q", path)
	}
	return &objectMetadataBlob{
		body:        body,
		contentType: sniffBlobContentType(path),
	}, nil
}

// sniffBlobContentType picks a reasonable on-the-wire Content-Type
// from a file's extension. The mapping is intentionally short — we
// cover the cases consumers actually use; everything else falls
// back to application/octet-stream and can be overridden via
// WithObjectMetadataContentType.
func sniffBlobContentType(path string) string {
	switch ext := strings.ToLower(filepath.Ext(path)); ext {
	case ".xml":
		return "application/xml"
	case ".json":
		return "application/json"
	case ".yaml", ".yml":
		return "application/yaml"
	case ".txt":
		return "text/plain"
	case ".csv":
		return "text/csv"
	default:
		return "application/octet-stream"
	}
}

// ReservedObjectMetadataKeys lists the keys the origin populates
// itself; the client refuses to forward them so users get a clear
// error rather than a silent server-side drop.
var ReservedObjectMetadataKeys = []string{"path", "size", "etag", "created_at"}

// loadObjectMetadataFile reads and validates the JSON file at the
// supplied path. Returns the parsed map. Errors out cleanly on
// reserved keys, nested structures, or non-scalar values so the user
// finds out before the upload starts.
//
// This is a package-private helper. Public callers should use the
// WithObjectMetadataFile transfer option, which dispatches here as
// part of NewTransferJob's option-apply pass.
func loadObjectMetadataFile(path string) (map[string]any, error) {
	if path == "" {
		return nil, errors.New("metadata file path is empty")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Wrapf(err, "reading metadata file %q", path)
	}
	return parseObjectMetadataJSON(raw)
}

// parseObjectMetadataJSON parses a single JSON object into the
// scalar-only map[string]any the upload header carries. We use
// json.Decoder with UseNumber so integers stay distinct from floats
// — the origin's SFV parser preserves typed values, and "the user
// wrote 4172, not 4172.0" survives end to end.
func parseObjectMetadataJSON(data []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var top any
	if err := dec.Decode(&top); err != nil {
		return nil, errors.Wrap(err, "metadata JSON does not parse")
	}
	obj, ok := top.(map[string]any)
	if !ok {
		return nil, errors.Errorf("metadata JSON must be a JSON object at the top level (got %T)", top)
	}

	out := make(map[string]any, len(obj))
	for k, v := range obj {
		if isReservedObjectMetadataKey(k) {
			return nil, errors.Errorf(
				"metadata key %q is reserved (set by the origin); cannot be supplied by the client. Reserved keys: %s",
				k, strings.Join(ReservedObjectMetadataKeys, ", "),
			)
		}
		coerced, err := coerceJSONScalar(v)
		if err != nil {
			return nil, errors.Wrapf(err, "metadata key %q", k)
		}
		out[k] = coerced
	}
	return out, nil
}

func isReservedObjectMetadataKey(k string) bool {
	for _, r := range ReservedObjectMetadataKeys {
		if k == r {
			return true
		}
	}
	return false
}

// coerceJSONScalar maps a single JSON value into the typed Go form
// the SFV renderer wants. Nested objects and arrays are explicitly
// rejected — the origin parser refuses inner lists in v1 and there's
// no point shipping a request that will be silently lossy.
func coerceJSONScalar(v any) (any, error) {
	switch x := v.(type) {
	case nil:
		return nil, errors.New("null is not a supported metadata value")
	case bool, string:
		return x, nil
	case json.Number:
		// Prefer integer; fall back to float64 if there's a fraction
		// or exponent.
		if i, err := x.Int64(); err == nil {
			return i, nil
		}
		f, err := x.Float64()
		if err != nil {
			return nil, errors.Wrapf(err, "number %q is neither integer nor decimal", string(x))
		}
		return f, nil
	case map[string]any:
		return nil, errors.New("nested objects are not supported in v1; values must be string/number/boolean")
	case []any:
		return nil, errors.New("arrays are not supported in v1; values must be string/number/boolean")
	default:
		return nil, errors.Errorf("unsupported metadata value type %T", v)
	}
}

// buildObjectMetadataHeader renders the supplied map as an RFC 9651
// Structured Fields dictionary, suitable for use as the value of
// X-Pelican-Object-Metadata. Returns ("", nil) for an empty/nil
// input so callers can omit the header entirely.
func buildObjectMetadataHeader(fields map[string]any) (string, error) {
	if len(fields) == 0 {
		return "", nil
	}
	dict := httpsfv.NewDictionary()
	// Iterate in sorted order so the rendered header is deterministic
	// (helps tests and log readability — SFV does preserve order, but
	// Go map iteration does not).
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		item, err := scalarToSFVItem(fields[k])
		if err != nil {
			return "", errors.Wrapf(err, "metadata key %q", k)
		}
		dict.Add(k, item)
	}
	return httpsfv.Marshal(dict)
}

func scalarToSFVItem(v any) (httpsfv.Item, error) {
	switch x := v.(type) {
	case string:
		return httpsfv.NewItem(x), nil
	case bool:
		return httpsfv.NewItem(x), nil
	case int64:
		return httpsfv.NewItem(x), nil
	case int:
		return httpsfv.NewItem(int64(x)), nil
	case float64:
		return httpsfv.NewItem(x), nil
	default:
		return httpsfv.Item{}, fmt.Errorf("cannot encode %T as a Structured Field item", v)
	}
}
