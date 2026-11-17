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
	"go.opentelemetry.io/otel/attribute"
)

// Attribute keys shared by more than one service.  Keys used by a single
// service are defined in that service's own package.
const (
	// AttrJobID is the X-Pelican-JobId of the transfer, which joins a trace to
	// the job's logs and transfer ads.
	AttrJobID = attribute.Key("pelican.job_id")
	// AttrObjectPath is the object's path within the federation, without
	// any query string.
	AttrObjectPath = attribute.Key("pelican.object.path")
	// AttrNamespace is the federation namespace prefix serving the object.
	AttrNamespace = attribute.Key("pelican.namespace")
	// AttrFederation is the federation's discovery URL.
	AttrFederation = attribute.Key("pelican.federation")
	// AttrTransferBytes is the number of object bytes moved.
	AttrTransferBytes = attribute.Key("pelican.transfer.bytes")
)

// JobID returns the pelican.job_id attribute.
func JobID(v string) attribute.KeyValue { return AttrJobID.String(v) }

// ObjectPath returns the pelican.object.path attribute.
func ObjectPath(v string) attribute.KeyValue { return AttrObjectPath.String(v) }

// Namespace returns the pelican.namespace attribute.
func Namespace(v string) attribute.KeyValue { return AttrNamespace.String(v) }

// Federation returns the pelican.federation attribute.
func Federation(v string) attribute.KeyValue { return AttrFederation.String(v) }

// TransferBytes returns the pelican.transfer.bytes attribute.
func TransferBytes(v int64) attribute.KeyValue { return AttrTransferBytes.Int64(v) }
