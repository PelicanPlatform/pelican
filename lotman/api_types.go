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

package lotman

// Request and response shapes for the /api/v1.0/lots/* HTTP surface.
//
// Conventions:
//   - GET endpoints take their inputs from the URL path or query string
//     (decoded via gin's `form` tag binder).
//   - POST and PATCH endpoints take their inputs from a JSON body
//     (decoded via gin's `json` tag binder).
//   - DELETE endpoints take their inputs from the URL path only.
//   - All public JSON and form field names are camelCase. The internal
//     lotman Lot/MPA/LotPath/RestrictiveMPA/LotUsage/AvailableCapacity
//     types use snake_case keys because that schema is the wire format
//     used to communicate with the lotman C library; the API boundary
//     translates between the two via the *Input request DTOs and the
//     project*Response helpers below.

// LotPathInput is the camelCase request-side counterpart to lotman's
// internal LotPath struct.
type LotPathInput struct {
	Path      string `json:"path" binding:"required"`
	Recursive bool   `json:"recursive"`
}

// MPAInput is the request-side projection of an MPA. Each field is a
// pointer so that PATCH requests can distinguish "field not present"
// from "field zero". Time fields are milliseconds since epoch.
//
// DedicatedGB is required for create requests (enforced in
// applyCreateLotDefaults) so reservations always have an explicit size
// budget; for PATCH the field is optional like every other.
type MPAInput struct {
	DedicatedGB      *float64 `json:"dedicatedGB,omitempty"`
	OpportunisticGB  *float64 `json:"opportunisticGB,omitempty"`
	MaxNumObjects    *int64   `json:"maxNumObjects,omitempty"`
	CreationTimeMs   *int64   `json:"creationTimeMs,omitempty"`
	ExpirationTimeMs *int64   `json:"expirationTimeMs,omitempty"`
	DeletionTimeMs   *int64   `json:"deletionTimeMs,omitempty"`
}

// ParentAttributionInput is the request-side projection of
// ParentAttribution.
type ParentAttributionInput struct {
	DedicatedGB     *float64 `json:"dedicatedGB,omitempty"`
	OpportunisticGB *float64 `json:"opportunisticGB,omitempty"`
	MaxNumObjects   *int64   `json:"maxNumObjects,omitempty"`
}

// CreateLotRequest is the JSON body accepted by POST /api/v1.0/lots.
//
// LotName is OPTIONAL: when omitted, the server mints a UUID-v4 reservation
// identifier and returns it on the response. Callers should treat the
// returned reservationId as the canonical handle for the lot.
//
// Owner and Parents are intentionally not accepted from the caller: Pelican
// derives them from the request's authentication context and the lot's
// path, respectively. ParentAttributions is optional and used only when
// strict_hierarchy is enabled.
//
// ManagementPolicyAttrs is required, and within it DedicatedGB is also
// required: a reservation without an explicit size budget would either be
// unbounded (dangerous) or zero-sized (useless), so neither is a
// reasonable default.
type CreateLotRequest struct {
	// LotName is an optional caller-supplied reservation identifier. If
	// empty (the recommended usage), the server generates a UUID.
	LotName               string                            `json:"lotName,omitempty"`
	Paths                 []LotPathInput                    `json:"paths" binding:"required,min=1"`
	ManagementPolicyAttrs *MPAInput                         `json:"managementPolicyAttrs" binding:"required"`
	ParentAttributions    map[string]ParentAttributionInput `json:"parentAttributions,omitempty"`
}

// PatchLotRequest is the JSON body accepted by PATCH /api/v1.0/lots/:lotName.
// Only MPA fields and ParentAttributions are honored. Owner, parents and paths
// are owned by Pelican and cannot be modified through this surface.
type PatchLotRequest struct {
	ManagementPolicyAttrs *MPAInput                         `json:"managementPolicyAttrs,omitempty"`
	ParentAttributions    map[string]ParentAttributionInput `json:"parentAttributions,omitempty"`
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
	ReclaimStatusAlreadyReclaimed ReclaimStatus = "alreadyReclaimed"
)

// ReclaimLotResponse is the JSON body returned by POST /api/v1.0/lots/:lotName/reclaim.
type ReclaimLotResponse struct {
	LotName       string        `json:"lotName"`
	Status        ReclaimStatus `json:"status"`
	Reason        string        `json:"reason,omitempty"`
	ReclaimedAtMs int64         `json:"reclaimedAtMs"`
}

// ListLotsByPathQuery binds the query string for GET /api/v1.0/lots/by-path.
//
// Only Path is required. FromMs/ToMs default to "now" when omitted; lotman
// requires a non-empty (strictly increasing) interval, so the server
// nudges toMs to fromMs+1 for point queries.
type ListLotsByPathQuery struct {
	Path             string `form:"path" binding:"required"`
	Recursive        bool   `form:"recursive,default=false"`
	IncludeReclaimed bool   `form:"includeReclaimed,default=false"`
	FromMs           int64  `form:"fromMs"`
	ToMs             int64  `form:"toMs"`
}

// CapacityQuery binds the query string for GET /api/v1.0/lots/by-path/capacity.
type CapacityQuery struct {
	// Path is the parent lot's path. The endpoint resolves the path to the
	// owning lot and then queries available capacity attributable to its
	// direct children over [FromMs, ToMs).
	Path   string `form:"path" binding:"required"`
	FromMs int64  `form:"fromMs"`
	ToMs   int64  `form:"toMs"`
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
	LotName  string   `json:"lotName"`
	Children []string `json:"children"`
}

// LotListResponse is the JSON body returned by GET /api/v1.0/lots.
type LotListResponse struct {
	Lots []string `json:"lots"`
}

// ReservationStatus is the lifecycle status reported by the Reservation
// projection. It is computed from the lot's MPA timestamps.
type ReservationStatus string

const (
	// ReservationStatusPending: now < creationTime. The reservation has
	// been created but its activation window has not yet begun.
	ReservationStatusPending ReservationStatus = "pending"
	// ReservationStatusActive: creationTime <= now < expirationTime.
	ReservationStatusActive ReservationStatus = "active"
	// ReservationStatusExpired: expirationTime <= now < deletionTime.
	// Capacity may still be charged but no new admissions are accepted.
	ReservationStatusExpired ReservationStatus = "expired"
	// ReservationStatusDeleted: deletionTime <= now. The lot is eligible
	// for purge.
	ReservationStatusDeleted ReservationStatus = "deleted"
	// ReservationStatusUnknown: the lot has no MPA or its timestamps are
	// missing; status cannot be derived.
	ReservationStatusUnknown ReservationStatus = "unknown"
)

// LotPathView is the camelCase response-side counterpart to lotman's
// internal LotPath.
type LotPathView struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive"`
	LotName   string `json:"lotName,omitempty"`
}

// Reservation is the stable public projection of a lotman Lot record. It
// is the response shape for POST /api/v1.0/lots and GET /api/v1.0/lots/{name}
// and is intentionally decoupled from lotman's internal Lot struct so the
// public contract can evolve independently. All time fields are milliseconds
// since epoch.
type Reservation struct {
	// ReservationID is the canonical handle for the reservation; it is
	// the lotman lot name.
	ReservationID string        `json:"reservationId"`
	Paths         []LotPathView `json:"paths,omitempty"`
	// Owner is the namespace issuer URL responsible for this reservation.
	Owner string `json:"owner,omitempty"`
	// Parents are the lot names this reservation is attributed to.
	Parents          []string          `json:"parents,omitempty"`
	Status           ReservationStatus `json:"status"`
	DedicatedGB      *float64          `json:"dedicatedGB,omitempty"`
	OpportunisticGB  *float64          `json:"opportunisticGB,omitempty"`
	MaxNumObjects    *int64            `json:"maxNumObjects,omitempty"`
	CreationTimeMs   int64             `json:"creationTimeMs,omitempty"`
	ExpirationTimeMs int64             `json:"expirationTimeMs,omitempty"`
	DeletionTimeMs   int64             `json:"deletionTimeMs,omitempty"`
}

// AvailableCapacityResponse is the camelCase response shape for
// GET /api/v1.0/lots/by-path/capacity.
type AvailableCapacityResponse struct {
	AvailableDedicatedGB     float64 `json:"availableDedicatedGB"`
	AvailableOpportunisticGB float64 `json:"availableOpportunisticGB"`
	AvailableMaxNumObjects   int64   `json:"availableMaxNumObjects"`
	AvailableTotalGB         float64 `json:"availableTotalGB"`
	PeakDedicatedGB          float64 `json:"peakDedicatedGB"`
	PeakOpportunisticGB      float64 `json:"peakOpportunisticGB"`
	PeakMaxNumObjects        int64   `json:"peakMaxNumObjects"`
	PeakTotalGB              float64 `json:"peakTotalGB"`
}

// UsageAxisFloatView is a camelCase projection of UsageMapFloat.
type UsageAxisFloatView struct {
	SelfContrib     float64 `json:"selfContrib,omitempty"`
	ChildrenContrib float64 `json:"childrenContrib,omitempty"`
	Total           float64 `json:"total"`
}

// UsageAxisIntView is a camelCase projection of UsageMapInt.
type UsageAxisIntView struct {
	SelfContrib     int64 `json:"selfContrib,omitempty"`
	ChildrenContrib int64 `json:"childrenContrib,omitempty"`
	Total           int64 `json:"total"`
}

// LotUsageResponse is the camelCase response shape for
// GET /api/v1.0/lots/{lotName}/usage.
type LotUsageResponse struct {
	GBBeingWritten      *UsageAxisFloatView `json:"gbBeingWritten,omitempty"`
	ObjectsBeingWritten *UsageAxisIntView   `json:"objectsBeingWritten,omitempty"`
	DedicatedGB         *UsageAxisFloatView `json:"dedicatedGB,omitempty"`
	OpportunisticGB     *UsageAxisFloatView `json:"opportunisticGB,omitempty"`
	NumObjects          *UsageAxisIntView   `json:"numObjects,omitempty"`
	TotalGB             *UsageAxisFloatView `json:"totalGB,omitempty"`
}

// PolicyAxisFloatView is a camelCase projection of LotValueMapFloat.
type PolicyAxisFloatView struct {
	LotName string  `json:"lotName"`
	Value   float64 `json:"value"`
}

// PolicyAxisIntView is a camelCase projection of LotValueMapInt.
type PolicyAxisIntView struct {
	LotName string `json:"lotName"`
	Value   int64  `json:"value"`
}

// LotPolicyResponse is the camelCase response shape for
// GET /api/v1.0/lots/{lotName}/policy. Each axis carries the most-restrictive
// value across the lot's ancestors and the lot name from which the
// restriction originates.
type LotPolicyResponse struct {
	DedicatedGB      PolicyAxisFloatView `json:"dedicatedGB"`
	OpportunisticGB  PolicyAxisFloatView `json:"opportunisticGB"`
	MaxNumObjects    PolicyAxisIntView   `json:"maxNumObjects"`
	CreationTimeMs   PolicyAxisIntView   `json:"creationTimeMs"`
	ExpirationTimeMs PolicyAxisIntView   `json:"expirationTimeMs"`
	DeletionTimeMs   PolicyAxisIntView   `json:"deletionTimeMs"`
}
