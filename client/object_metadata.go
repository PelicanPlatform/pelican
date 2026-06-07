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
	"os"
	"sort"
	"strings"

	"github.com/dunglas/httpsfv"
	"github.com/pkg/errors"
)

// ObjectMetadataHeaderName is the HTTP header that carries the
// rendered Structured Fields dictionary on the upload PUT request.
// Kept as a public constant so other clients can reuse it.
const ObjectMetadataHeaderName = "X-Pelican-Object-Metadata"

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
