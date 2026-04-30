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

// File object_metadata_header.go translates the inbound
// X-Pelican-Object-Metadata header (an RFC 9651 Structured Field Values
// dictionary) into a JSON-ready map[string]any that we will inline into
// the outgoing webhook body.
//
// We deliberately use Structured Fields on the way *in* because they
// have a typed grammar that survives header canonicalization, but we
// emit JSON on the way *out* (the webhook body), which is more
// ergonomic for receivers.

package origin_serve

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/dunglas/httpsfv"
)

// ObjectMetadataHeader is the request header clients use to attach custom
// fields to an upload. Its value is parsed as an RFC 9651 dictionary.
const ObjectMetadataHeader = "X-Pelican-Object-Metadata"

// ReservedCustomFieldKeys lists keys that the client cannot set in the
// header — they are populated by the origin from the storage commit
// itself.
var ReservedCustomFieldKeys = []string{"path", "size", "etag", "created_at"}

// ParseObjectMetadataHeader parses the value of an X-Pelican-Object-Metadata
// header. An empty / absent value yields an empty (non-nil) map. The
// returned map's values are JSON-serializable: strings, integers, floats,
// booleans, and (for byte sequences) base64-encoded strings.
//
// Reserved keys (see ReservedCustomFieldKeys) are silently dropped with
// a non-fatal error if present; the caller may inspect the error to log
// or count rejections.
func ParseObjectMetadataHeader(value string) (map[string]any, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return map[string]any{}, nil
	}
	dict, err := httpsfv.UnmarshalDictionary([]string{value})
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", ObjectMetadataHeader, err)
	}

	names := dict.Names()
	out := make(map[string]any, len(names))
	var rejected []string
	for _, key := range names {
		if isReservedCustomKey(key) {
			rejected = append(rejected, key)
			continue
		}
		member, _ := dict.Get(key)
		v, convErr := dictMemberToJSON(member)
		if convErr != nil {
			return nil, fmt.Errorf("parse %s key %q: %w", ObjectMetadataHeader, key, convErr)
		}
		out[key] = v
	}
	if len(rejected) > 0 {
		return out, fmt.Errorf("ignored reserved keys: %s", strings.Join(rejected, ", "))
	}
	return out, nil
}

func isReservedCustomKey(key string) bool {
	for _, r := range ReservedCustomFieldKeys {
		if key == r {
			return true
		}
	}
	return false
}

// dictMemberToJSON converts an SFV dictionary member into a JSON value.
// Inner lists and parameterized items are intentionally rejected in v1
// rather than producing a lossy translation.
func dictMemberToJSON(member httpsfv.Member) (any, error) {
	switch m := member.(type) {
	case httpsfv.Item:
		return itemValueToJSON(m.Value)
	case *httpsfv.Item:
		if m == nil {
			return nil, errors.New("nil item")
		}
		return itemValueToJSON(m.Value)
	case httpsfv.InnerList:
		return nil, errors.New("inner lists are not supported in v1")
	case *httpsfv.InnerList:
		return nil, errors.New("inner lists are not supported in v1")
	default:
		return nil, fmt.Errorf("unsupported dictionary member type %T", member)
	}
}

// itemValueToJSON maps the Go types httpsfv emits for SFV bare item
// values into JSON-serializable Go values.
func itemValueToJSON(v any) (any, error) {
	switch x := v.(type) {
	case string:
		return x, nil
	case bool:
		return x, nil
	case int64:
		return x, nil
	case float64:
		return x, nil
	case []byte:
		// JSON has no native byte type; emit as a base64 std-encoded
		// string with a `:` prefix to match the SFV spelling, so a
		// receiver who cares can recover the original bytes.
		return ":" + base64.StdEncoding.EncodeToString(x) + ":", nil
	case httpsfv.Token:
		// Tokens (RFC 9651) are unquoted bare words; render as plain
		// strings since JSON has no token type.
		return string(x), nil
	default:
		return nil, fmt.Errorf("unsupported item value type %T", v)
	}
}
