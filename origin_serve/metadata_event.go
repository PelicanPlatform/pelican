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

// File metadata_event.go defines the on-the-wire event the V2 origin
// posts to a configured metadata endpoint after a successful object
// commit, plus the JSON shape we render. This is the contract between
// the origin and any third-party metadata-consuming service.
//
// The webhook body is GitHub-/Stripe-style: a top-level `id` (UUIDv4),
// a `type` discriminator, a `timestamp`, and a `namespace` plus an
// `object` sub-object. Custom uploader-supplied fields are inlined
// into `object` rather than nested under an "extra" key.

package origin_serve

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// ObjectCommitEventType is the discriminator written into the wire
// `type` field. Constant today; may be joined by `object.deleted` etc.
const ObjectCommitEventType = "object.committed"

// CustomFields is the fully-translated, JSON-ready custom field map
// that came in via X-Pelican-Object-Metadata. We keep it as a typed
// alias for readability.
type CustomFields map[string]any

// ObjectCommitEvent is the in-memory representation of a publishable
// object-commit event. Its JSON form (per MarshalJSON below) is the
// webhook wire shape.
type ObjectCommitEvent struct {
	// ID is a server-side UUIDv4. Stable across retries; used for
	// receiver-side dedup.
	ID string

	// Type is the event-type discriminator. Today: ObjectCommitEventType.
	Type string

	// Timestamp is when this event was first generated.
	Timestamp time.Time

	// Namespace is the federation prefix of the export this object
	// belongs to.
	Namespace string

	// ObjectPath is the federation-relative path of the object.
	ObjectPath string

	// ObjectSize is the size in bytes as reported by the storage
	// backend after commit.
	ObjectSize int64

	// ETag is the entity tag computed by the storage backend (eg the
	// WebDAV-generated ETag). The origin does not introduce its own
	// hashing scheme.
	ETag string

	// ObjectCreated is the storage-reported commit / mtime.
	ObjectCreated time.Time

	// CustomFields are uploader-supplied fields (parsed from the
	// X-Pelican-Object-Metadata header). Reserved keys are stripped
	// at parse time.
	CustomFields CustomFields
}

// NewObjectCommitEvent constructs a fresh event with a server-generated
// UUID and Type/Timestamp pre-populated.
func NewObjectCommitEvent(namespace, objectPath string, size int64, etag string, created time.Time, custom CustomFields) *ObjectCommitEvent {
	return &ObjectCommitEvent{
		ID:            uuid.NewString(),
		Type:          ObjectCommitEventType,
		Timestamp:     time.Now().UTC(),
		Namespace:     namespace,
		ObjectPath:    objectPath,
		ObjectSize:    size,
		ETag:          etag,
		ObjectCreated: created.UTC(),
		CustomFields:  custom,
	}
}

// MarshalJSON renders the event in the wire shape:
//
//	{
//	  "id": "...", "type": "object.committed", "timestamp": "...",
//	  "namespace": "/foo",
//	  "object": { "path": ..., "size": ..., "etag": ..., "created_at": ..., ...inlined customs }
//	}
func (e *ObjectCommitEvent) MarshalJSON() ([]byte, error) {
	if e == nil {
		return nil, errors.New("nil ObjectCommitEvent")
	}
	obj := make(map[string]any, len(e.CustomFields)+4)
	obj["path"] = e.ObjectPath
	obj["size"] = e.ObjectSize
	obj["etag"] = e.ETag
	obj["created_at"] = e.ObjectCreated.UTC().Format(time.RFC3339Nano)
	for k, v := range e.CustomFields {
		// Inline custom fields. Reserved keys cannot collide because
		// they are stripped at parse time.
		obj[k] = v
	}
	wire := struct {
		ID        string         `json:"id"`
		Type      string         `json:"type"`
		Timestamp string         `json:"timestamp"`
		Namespace string         `json:"namespace"`
		Object    map[string]any `json:"object"`
	}{
		ID:        e.ID,
		Type:      e.Type,
		Timestamp: e.Timestamp.UTC().Format(time.RFC3339Nano),
		Namespace: e.Namespace,
		Object:    obj,
	}
	return json.Marshal(wire)
}
