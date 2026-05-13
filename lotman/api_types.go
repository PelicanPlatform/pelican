//go:build linux && !ppc64le

/***************************************************************
*
* Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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

package lotman

// Request and response shapes for the /api/v1.0/lots/* HTTP surface.
//
// Conventions:
//   - GET endpoints take their inputs from the URL path or query string
//     (decoded via gin's `form` tag binder).
//   - POST and PATCH endpoints take their inputs from a JSON body
//     (decoded via gin's `json` tag binder).
//   - DELETE endpoints take their inputs from the URL path only.

// CreateLotRequest is the JSON body accepted by POST /api/v1.0/lots.
//
// LotName is OPTIONAL: when omitted, the server mints a UUID-v4 reservation
// identifier and returns it on the response. Callers should treat the
// returned reservation_id as the canonical handle for the lot.
//
// Owner and Parents are intentionally not accepted from the caller: Pelican
// derives them from the request's authentication context and the lot's
// path, respectively. ParentAttributions is optional and used only when
// strict_hierarchy is enabled.
type CreateLotRequest struct {
	// LotName is an optional caller-supplied reservation identifier. If
	// empty (the recommended usage), the server generates a UUID.
	LotName            string                       `json:"lot_name,omitempty"`
	Paths              []LotPath                    `json:"paths" binding:"required,min=1"`
	MPA                *MPA                         `json:"management_policy_attrs,omitempty"`
	ParentAttributions map[string]ParentAttribution `json:"parent_attributions,omitempty"`
}

// PatchLotRequest is the JSON body accepted by PATCH /api/v1.0/lots/:lotName.
// Only MPA fields and ParentAttributions are honored. Owner, parents and paths
// are owned by Pelican and cannot be modified through this surface.
type PatchLotRequest struct {
	MPA                *MPA                         `json:"management_policy_attrs,omitempty"`
	ParentAttributions map[string]ParentAttribution `json:"parent_attributions,omitempty"`
}

// ReclaimLotRequest is the JSON body accepted by POST /api/v1.0/lots/:lotName/reclaim.
//
// Reclamation is an audit-trail event: the server stamps the wall-clock
// time. Clients cannot backdate reclamation events; only Reason is honored
// from the request body.
type ReclaimLotRequest struct {
	// Reason is a free-form audit string recorded with the reclamation event.
	Reason string `json:"reason,omitempty"`
}

// ReclaimStatus is the documented status enum returned by reclaim.
type ReclaimStatus string

const (
	// ReclaimStatusReclaimed indicates the lot was newly marked reclaimed
	// by this call (lotman returned a non-zero rows-affected count).
	ReclaimStatusReclaimed ReclaimStatus = "reclaimed"
	// ReclaimStatusAlreadyReclaimed indicates the lot was already in a
	// reclaimed state before this call (lotman returned zero rows-affected).
	ReclaimStatusAlreadyReclaimed ReclaimStatus = "already_reclaimed"
)

// ReclaimLotResponse is the JSON body returned by POST /api/v1.0/lots/:lotName/reclaim.
type ReclaimLotResponse struct {
	LotName       string        `json:"lot_name"`
	Status        ReclaimStatus `json:"status"`
	Reason        string        `json:"reason,omitempty"`
	ReclaimedAtMs int64         `json:"reclaimed_at_ms"`
}

// ListLotsByPathQuery binds the query string for GET /api/v1.0/lots/by-path.
//
// Only Path is required. FromMs/ToMs default to "now" when omitted; lotman
// requires a non-empty (strictly increasing) interval, so the server
// nudges to_ms to from_ms+1 for point queries.
type ListLotsByPathQuery struct {
	Path             string `form:"path" binding:"required"`
	Recursive        bool   `form:"recursive,default=false"`
	IncludeReclaimed bool   `form:"include_reclaimed,default=false"`
	FromMs           int64  `form:"from_ms"`
	ToMs             int64  `form:"to_ms"`
}

// CapacityQuery binds the query string for GET /api/v1.0/lots/by-path/capacity.
type CapacityQuery struct {
	// Path is the parent lot's path. The endpoint resolves the path to the
	// owning lot and then queries available capacity attributable to its
	// direct children over [FromMs, ToMs).
	Path   string `form:"path" binding:"required"`
	FromMs int64  `form:"from_ms"`
	ToMs   int64  `form:"to_ms"`
}

// GetLotQuery binds the query string for GET /api/v1.0/lots/:lotName.
type GetLotQuery struct {
	Recursive bool `form:"recursive,default=false"`
}

// ListLotsQuery binds the query string for GET /api/v1.0/lots.
type ListLotsQuery struct {
	// Recursive=true returns the entire descendant tree rooted at "root".
	Recursive bool `form:"recursive,default=true"`
	// Owner, when non-empty, restricts the result to lots whose Owner equals
	// the supplied issuer URL. Useful for namespace owners who want to
	// enumerate "their" reservations.
	Owner string `form:"owner"`
}

// LotChildrenResponse is the JSON body returned by GET /api/v1.0/lots/:lotName/children.
type LotChildrenResponse struct {
	LotName  string   `json:"lot_name"`
	Children []string `json:"children"`
}

// LotListResponse is the JSON body returned by GET /api/v1.0/lots.
type LotListResponse struct {
	Lots []string `json:"lots"`
}

// ReservationStatus is the lifecycle status reported by the Reservation
// projection. It is computed from the lot's MPA timestamps and the
// (optional) reclamation marker.
type ReservationStatus string

const (
	// ReservationStatusPending: now < creation_time. The reservation has
	// been created but its activation window has not yet begun.
	ReservationStatusPending ReservationStatus = "pending"
	// ReservationStatusActive: creation_time <= now < expiration_time and
	// the lot has not been reclaimed.
	ReservationStatusActive ReservationStatus = "active"
	// ReservationStatusExpired: expiration_time <= now < deletion_time.
	// Capacity may still be charged but no new admissions are accepted.
	ReservationStatusExpired ReservationStatus = "expired"
	// ReservationStatusDeleted: deletion_time <= now. The lot is eligible
	// for purge.
	ReservationStatusDeleted ReservationStatus = "deleted"
	// ReservationStatusReclaimed: an explicit reclaim event has been
	// recorded against the lot.
	ReservationStatusReclaimed ReservationStatus = "reclaimed"
	// ReservationStatusUnknown: the lot has no MPA or its timestamps are
	// missing; status cannot be derived.
	ReservationStatusUnknown ReservationStatus = "unknown"
)

// Reservation is the stable public projection of a lotman Lot record. It
// is the response shape for POST /api/v1.0/lots and is intentionally
// decoupled from lotman's internal Lot struct so the public contract can
// evolve independently. All time fields are milliseconds since epoch.
type Reservation struct {
	// ReservationID is the canonical handle for the reservation; it is
	// the lotman lot name.
	ReservationID string    `json:"reservation_id"`
	Paths         []LotPath `json:"paths,omitempty"`
	// Owner is the namespace issuer URL responsible for this reservation.
	Owner string `json:"owner,omitempty"`
	// Parents are the lot names this reservation is attributed to.
	Parents          []string          `json:"parents,omitempty"`
	Status           ReservationStatus `json:"status"`
	DedicatedGB      *float64          `json:"dedicated_GB,omitempty"`
	OpportunisticGB  *float64          `json:"opportunistic_GB,omitempty"`
	MaxNumObjects    *int64            `json:"max_num_objects,omitempty"`
	CreationTimeMs   int64             `json:"creation_time_ms,omitempty"`
	ExpirationTimeMs int64             `json:"expiration_time_ms,omitempty"`
	DeletionTimeMs   int64             `json:"deletion_time_ms,omitempty"`
}
