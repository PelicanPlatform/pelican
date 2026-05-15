//go:build linux && !ppc64le

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

// HTTP handlers for the /api/v1.0/lots/* surface.
//
// All routes live under /api/v1.0/lots and are wired by RegisterLotsAPI.
// Auth lives in lotman_auth.go; defaulting lives in api_defaults.go;
// request/response shapes live in api_types.go.

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// abortWithErr logs the underlying error and writes a SimpleApiResp with a
// sanitized message. The raw err.Error() is NEVER returned to the caller:
// lotman C errors and DB-layer errors can leak file paths, internal column
// names and similar implementation details.
func abortWithErr(ctx *gin.Context, status int, msg string, err error) {
	if err != nil {
		log.Debugf("lotman API %s %s -> %d: %s: %v", ctx.Request.Method, ctx.Request.URL.Path, status, msg, err)
	} else {
		log.Debugf("lotman API %s %s -> %d: %s", ctx.Request.Method, ctx.Request.URL.Path, status, msg)
	}
	ctx.AbortWithStatusJSON(status, server_structs.SimpleApiResp{
		Status: server_structs.RespFailed,
		Msg:    msg,
	})
}

// computeReservationStatus derives a Reservation lifecycle status from a
// Lot's MPA timestamps.
func computeReservationStatus(lot *Lot, nowMs int64) ReservationStatus {
	if lot.MPA == nil {
		return ReservationStatusUnknown
	}
	if lot.MPA.CreationTime != nil && nowMs < lot.MPA.CreationTime.Value {
		return ReservationStatusPending
	}
	if lot.MPA.DeletionTime != nil && nowMs >= lot.MPA.DeletionTime.Value {
		return ReservationStatusDeleted
	}
	if lot.MPA.ExpirationTime != nil && nowMs >= lot.MPA.ExpirationTime.Value {
		return ReservationStatusExpired
	}
	return ReservationStatusActive
}

// projectLotPaths converts internal LotPath records to their camelCase
// public projection.
func projectLotPaths(in []LotPath) []LotPathView {
	if len(in) == 0 {
		return nil
	}
	out := make([]LotPathView, len(in))
	for i, p := range in {
		out[i] = LotPathView{Path: p.Path, Recursive: p.Recursive, LotName: p.LotName}
	}
	return out
}

// lotToReservation projects a lotman Lot record onto the stable public
// Reservation contract.
func lotToReservation(lot *Lot, nowMs int64) Reservation {
	r := Reservation{
		ReservationID: lot.LotName,
		Paths:         projectLotPaths(lot.Paths),
		Owner:         lot.Owner,
		Parents:       lot.Parents,
		Status:        computeReservationStatus(lot, nowMs),
	}
	if lot.MPA != nil {
		r.DedicatedGB = lot.MPA.DedicatedGB
		r.OpportunisticGB = lot.MPA.OpportunisticGB
		if lot.MPA.MaxNumObjects != nil {
			v := lot.MPA.MaxNumObjects.Value
			r.MaxNumObjects = &v
		}
		if lot.MPA.CreationTime != nil {
			r.CreationTimeMs = lot.MPA.CreationTime.Value
		}
		if lot.MPA.ExpirationTime != nil {
			r.ExpirationTimeMs = lot.MPA.ExpirationTime.Value
		}
		if lot.MPA.DeletionTime != nil {
			r.DeletionTimeMs = lot.MPA.DeletionTime.Value
		}
	}
	return r
}

// mpaInputToInternal converts the camelCase MPAInput accepted on the wire
// into the snake-cased lotman MPA struct used to talk to the C library.
// Nil-safe; nil in -> nil out.
func mpaInputToInternal(in *MPAInput) *MPA {
	if in == nil {
		return nil
	}
	out := &MPA{
		DedicatedGB:     in.DedicatedGB,
		OpportunisticGB: in.OpportunisticGB,
	}
	if in.MaxNumObjects != nil {
		out.MaxNumObjects = &Int64FromFloat{Value: *in.MaxNumObjects}
	}
	if in.CreationTimeMs != nil {
		out.CreationTime = &Int64FromFloat{Value: *in.CreationTimeMs}
	}
	if in.ExpirationTimeMs != nil {
		out.ExpirationTime = &Int64FromFloat{Value: *in.ExpirationTimeMs}
	}
	if in.DeletionTimeMs != nil {
		out.DeletionTime = &Int64FromFloat{Value: *in.DeletionTimeMs}
	}
	return out
}

// parentAttributionsInputToInternal converts the camelCase request map to
// the lotman-internal map shape.
func parentAttributionsInputToInternal(in map[string]ParentAttributionInput) map[string]ParentAttribution {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]ParentAttribution, len(in))
	for k, v := range in {
		pa := ParentAttribution{DedicatedGB: v.DedicatedGB, OpportunisticGB: v.OpportunisticGB}
		if v.MaxNumObjects != nil {
			pa.MaxNumObjects = &Int64FromFloat{Value: *v.MaxNumObjects}
		}
		out[k] = pa
	}
	return out
}

// pathInputsToInternal converts the request-side path list to the
// lotman-internal LotPath list.
func pathInputsToInternal(in []LotPathInput) []LotPath {
	if len(in) == 0 {
		return nil
	}
	out := make([]LotPath, len(in))
	for i, p := range in {
		out[i] = LotPath{Path: p.Path, Recursive: p.Recursive}
	}
	return out
}

// projectAvailableCapacity converts the lotman-internal capacity record to
// its camelCase public response shape.
func projectAvailableCapacity(in *AvailableCapacity) AvailableCapacityResponse {
	return AvailableCapacityResponse{
		AvailableDedicatedGB:     in.AvailableDedicatedGB,
		AvailableOpportunisticGB: in.AvailableOpportunisticGB,
		AvailableMaxNumObjects:   in.AvailableMaxNumObjects,
		AvailableTotalGB:         in.AvailableTotalGB,
		PeakDedicatedGB:          in.PeakDedicatedGB,
		PeakOpportunisticGB:      in.PeakOpportunisticGB,
		PeakMaxNumObjects:        in.PeakMaxNumObjects,
		PeakTotalGB:              in.PeakTotalGB,
	}
}

// projectLotUsage converts the lotman-internal usage record to its
// camelCase response shape, dropping axes the caller opted out of (zero
// totals collapse to omit).
func projectLotUsage(in *LotUsage) LotUsageResponse {
	floatView := func(m UsageMapFloat) *UsageAxisFloatView {
		if m.Total == 0 && m.SelfContrib == 0 && m.ChildrenContrib == 0 {
			return nil
		}
		return &UsageAxisFloatView{SelfContrib: m.SelfContrib, ChildrenContrib: m.ChildrenContrib, Total: m.Total}
	}
	intView := func(m UsageMapInt) *UsageAxisIntView {
		if m.Total.Value == 0 && m.SelfContrib.Value == 0 && m.ChildrenContrib.Value == 0 {
			return nil
		}
		return &UsageAxisIntView{SelfContrib: m.SelfContrib.Value, ChildrenContrib: m.ChildrenContrib.Value, Total: m.Total.Value}
	}
	return LotUsageResponse{
		GBBeingWritten:      floatView(in.GBBeingWritten),
		ObjectsBeingWritten: intView(in.ObjectsBeingWritten),
		DedicatedGB:         floatView(in.DedicatedGB),
		OpportunisticGB:     floatView(in.OpportunisticGB),
		NumObjects:          intView(in.NumObjects),
		TotalGB:             floatView(in.TotalGB),
	}
}

// projectRestrictiveMPA converts the lotman-internal RestrictiveMPA to its
// camelCase response shape.
func projectRestrictiveMPA(in *RestrictiveMPA) LotPolicyResponse {
	return LotPolicyResponse{
		DedicatedGB:      PolicyAxisFloatView{LotName: in.DedicatedGB.LotName, Value: in.DedicatedGB.Value},
		OpportunisticGB:  PolicyAxisFloatView{LotName: in.OpportunisticGB.LotName, Value: in.OpportunisticGB.Value},
		MaxNumObjects:    PolicyAxisIntView{LotName: in.MaxNumObjects.LotName, Value: in.MaxNumObjects.Value.Value},
		CreationTimeMs:   PolicyAxisIntView{LotName: in.CreationTime.LotName, Value: in.CreationTime.Value.Value},
		ExpirationTimeMs: PolicyAxisIntView{LotName: in.ExpirationTime.LotName, Value: in.ExpirationTime.Value.Value},
		DeletionTimeMs:   PolicyAxisIntView{LotName: in.DeletionTime.LotName, Value: in.DeletionTime.Value.Value},
	}
}

// listLots handles GET /api/v1.0/lots. It returns the names of all lots
// reachable from the synthetic root, optionally filtered by Owner.
//
// @Summary List all lots
// @Description Returns the names of every lot known to lotman, optionally
// @Description including only the descendants of the synthetic root. When
// @Description the `owner` query parameter is set, only lots whose Owner
// @Description matches are returned.
// @Tags lots
// @Produce json
// @Param recursive query bool false "Include all descendants of root (default true)"
// @Param owner query string false "Restrict to lots whose owner equals this issuer URL"
// @Success 200 {object} LotListResponse
// @Failure 401 {object} server_structs.SimpleApiResp
// @Failure 403 {object} server_structs.SimpleApiResp
// @Failure 500 {object} server_structs.SimpleApiResp
// @Router /api/v1.0/lots [get]
func listLots(ctx *gin.Context) {
	var q ListLotsQuery
	if err := ctx.ShouldBindQuery(&q); err != nil {
		abortWithErr(ctx, http.StatusBadRequest, "invalid query parameters", err)
		return
	}
	if _, ok := requireAuth(ctx, "root", token_scopes.Lot_Read); !ok {
		return
	}
	names, err := GetChildrenNames("root", q.Recursive, true)
	if err != nil {
		abortWithErr(ctx, http.StatusInternalServerError, "failed to enumerate lots", err)
		return
	}
	if q.Owner != "" {
		filtered := make([]string, 0, len(names))
		for _, name := range names {
			lot, err := GetLot(name, false)
			if err != nil {
				log.Debugf("listLots: skipping lot %s: %v", name, err)
				continue
			}
			if lot.Owner == q.Owner {
				filtered = append(filtered, name)
			}
		}
		names = filtered
	}
	ctx.JSON(http.StatusOK, LotListResponse{Lots: names})
}

// createLot handles POST /api/v1.0/lots.
//
// @Summary Create a new reservation (lot)
// @Description Creates a new reservation under the parent determined by
// @Description its first path. Owner is set from the request's authentication
// @Description context (namespace issuer for bearer tokens, federation issuer
// @Description for admin cookies); Parents are derived from the path. MPA
// @Description fields the caller omits are filled in with sensible defaults.
// @Description If lot_name is omitted, the server mints a UUID-v4 reservation
// @Description identifier and returns it in the response.
// @Tags lots
// @Accept json
// @Produce json
// @Param body body CreateLotRequest true "Reservation to create"
// @Success 201 {object} Reservation
// @Failure 400 {object} server_structs.SimpleApiResp
// @Failure 401 {object} server_structs.SimpleApiResp
// @Failure 403 {object} server_structs.SimpleApiResp
// @Failure 500 {object} server_structs.SimpleApiResp
// @Router /api/v1.0/lots [post]
func createLot(ctx *gin.Context) {
	var req CreateLotRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		abortWithErr(ctx, http.StatusBadRequest, "invalid request body", err)
		return
	}
	if len(req.Paths) > 1 {
		abortWithErr(ctx, http.StatusBadRequest, "lot creation with more than one path is not yet supported", nil)
		return
	}
	if err := applyCreateLotDefaults(&req, time.Now()); err != nil {
		abortWithErr(ctx, http.StatusBadRequest, "invalid managementPolicyAttrs", err)
		return
	}
	// Mint a UUID reservation identifier when the caller didn't supply one.
	// Per the API contract, callers should treat the returned reservationId
	// as the canonical handle.
	if req.LotName == "" {
		req.LotName = uuid.NewString()
	}

	lot := Lot{
		LotName:            req.LotName,
		Paths:              pathInputsToInternal(req.Paths),
		MPA:                mpaInputToInternal(req.ManagementPolicyAttrs),
		ParentAttributions: parentAttributionsInputToInternal(req.ParentAttributions),
	}
	res, ok := requireAuthForCreate(ctx, &lot)
	if !ok {
		return
	}
	if err := CreateLot(&lot, res.caller); err != nil {
		abortWithErr(ctx, http.StatusInternalServerError, "failed to create lot", err)
		return
	}
	// Re-fetch to capture lotman-derived fields like the assigned Owner,
	// Parents, etc. before projecting onto the public Reservation shape.
	created, err := GetLot(lot.LotName, false)
	if err != nil {
		// We successfully created the lot but can't read it back. Fall
		// back to the in-memory record so the caller still gets the
		// reservation_id.
		log.Warnf("createLot: lot %s created but read-back failed: %v", lot.LotName, err)
		created = &lot
	}
	ctx.JSON(http.StatusCreated, lotToReservation(created, time.Now().UnixMilli()))
}

// getLot handles GET /api/v1.0/lots/:lotName.
//
// @Summary Get a lot's full record as a Reservation projection
// @Tags lots
// @Produce json
// @Param lotName path string true "Lot name"
// @Param recursive query bool false "Include descendant aggregation (default false)"
// @Success 200 {object} Reservation
// @Failure 401 {object} server_structs.SimpleApiResp
// @Failure 403 {object} server_structs.SimpleApiResp
// @Failure 404 {object} server_structs.SimpleApiResp
// @Router /api/v1.0/lots/{lotName} [get]
func getLot(ctx *gin.Context) {
	lotName := ctx.Param("lotName")
	if lotName == "" {
		abortWithErr(ctx, http.StatusBadRequest, "missing :lotName path parameter", nil)
		return
	}
	var q GetLotQuery
	if err := ctx.ShouldBindQuery(&q); err != nil {
		abortWithErr(ctx, http.StatusBadRequest, "invalid query parameters", err)
		return
	}
	if _, ok := requireAuth(ctx, lotName, token_scopes.Lot_Read); !ok {
		return
	}
	lot, err := GetLot(lotName, q.Recursive)
	if err != nil {
		abortWithErr(ctx, http.StatusInternalServerError, "failed to fetch lot", err)
		return
	}
	ctx.JSON(http.StatusOK, lotToReservation(lot, time.Now().UnixMilli()))
}

// patchLot handles PATCH /api/v1.0/lots/:lotName.
//
// @Summary Modify a lot's MPA / parent attributions
// @Description Updates MPA fields or parent attributions on an existing
// @Description reservation. When MPA timestamps are modified, the resulting
// @Description record must satisfy creation_time < expiration_time <= deletion_time.
// @Tags lots
// @Accept json
// @Produce json
// @Param lotName path string true "Lot name"
// @Param body body PatchLotRequest true "Fields to update"
// @Success 200 {object} server_structs.SimpleApiResp
// @Failure 400 {object} server_structs.SimpleApiResp
// @Failure 401 {object} server_structs.SimpleApiResp
// @Failure 403 {object} server_structs.SimpleApiResp
// @Failure 500 {object} server_structs.SimpleApiResp
// @Router /api/v1.0/lots/{lotName} [patch]
func patchLot(ctx *gin.Context) {
	lotName := ctx.Param("lotName")
	if lotName == "" {
		abortWithErr(ctx, http.StatusBadRequest, "missing :lotName path parameter", nil)
		return
	}
	var req PatchLotRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		abortWithErr(ctx, http.StatusBadRequest, "invalid request body", err)
		return
	}
	if req.ManagementPolicyAttrs == nil && req.ParentAttributions == nil {
		abortWithErr(ctx, http.StatusBadRequest, "PATCH body must include at least one of managementPolicyAttrs or parentAttributions", nil)
		return
	}
	res, ok := requireAuth(ctx, lotName, token_scopes.Lot_Modify)
	if !ok {
		return
	}
	internalMPA := mpaInputToInternal(req.ManagementPolicyAttrs)
	// Validate MPA timestamp ordering against the post-PATCH state. Any
	// timestamp the caller didn't supply is read from the existing lot
	// so we can detect a partial update that would invert the ordering.
	if internalMPA != nil {
		existing, err := GetLot(lotName, false)
		if err != nil {
			abortWithErr(ctx, http.StatusInternalServerError, "failed to fetch lot for validation", err)
			return
		}
		if err := validatePatchedMPA(existing.MPA, internalMPA); err != nil {
			abortWithErr(ctx, http.StatusBadRequest, "invalid MPA timestamps", err)
			return
		}
	}
	upd := LotUpdate{
		LotName:            lotName,
		MPA:                internalMPA,
		ParentAttributions: parentAttributionsInputToInternal(req.ParentAttributions),
	}
	if err := UpdateLot(&upd, res.caller); err != nil {
		abortWithErr(ctx, http.StatusInternalServerError, "failed to update lot", err)
		return
	}
	ctx.JSON(http.StatusOK, server_structs.SimpleApiResp{
		Status: server_structs.RespOK,
		Msg:    "lot updated",
	})
}

// validatePatchedMPA checks that the union of the existing and patched MPA
// timestamps satisfies creation_time < expiration_time <= deletion_time.
// Either argument may be nil.
func validatePatchedMPA(existing, patched *MPA) error {
	pick := func(p, e *Int64FromFloat) int64 {
		if p != nil {
			return p.Value
		}
		if e != nil {
			return e.Value
		}
		return 0
	}
	var ePtr MPA
	if existing != nil {
		ePtr = *existing
	}
	creation := pick(patched.CreationTime, ePtr.CreationTime)
	expiration := pick(patched.ExpirationTime, ePtr.ExpirationTime)
	deletion := pick(patched.DeletionTime, ePtr.DeletionTime)
	// Only validate when at least one timestamp is present; lotman tolerates
	// MPAs that have no timestamps at all.
	if creation == 0 && expiration == 0 && deletion == 0 {
		return nil
	}
	if expiration != 0 && creation >= expiration {
		return errors.Errorf("creation_time (%d) must be < expiration_time (%d)", creation, expiration)
	}
	if deletion != 0 && expiration != 0 && expiration > deletion {
		return errors.Errorf("expiration_time (%d) must be <= deletion_time (%d)", expiration, deletion)
	}
	return nil
}

// deleteLot handles DELETE /api/v1.0/lots/:lotName.
//
// @Summary Delete a lot and all its descendants
// @Tags lots
// @Produce json
// @Param lotName path string true "Lot name"
// @Success 200 {object} server_structs.SimpleApiResp
// @Failure 401 {object} server_structs.SimpleApiResp
// @Failure 403 {object} server_structs.SimpleApiResp
// @Failure 500 {object} server_structs.SimpleApiResp
// @Router /api/v1.0/lots/{lotName} [delete]
func deleteLot(ctx *gin.Context) {
	lotName := ctx.Param("lotName")
	if lotName == "" {
		abortWithErr(ctx, http.StatusBadRequest, "missing :lotName path parameter", nil)
		return
	}
	res, ok := requireAuth(ctx, lotName, token_scopes.Lot_Delete)
	if !ok {
		return
	}
	if err := DeleteLotsRecursive(lotName, res.caller); err != nil {
		abortWithErr(ctx, http.StatusInternalServerError, "failed to delete lot", err)
		return
	}
	ctx.JSON(http.StatusOK, server_structs.SimpleApiResp{
		Status: server_structs.RespOK,
		Msg:    "lot deleted",
	})
}

// reclaimLot handles POST /api/v1.0/lots/:lotName/reclaim. Reclamation marks
// a lot's storage as reclaimed at the current wall-clock instant without
// removing the lot record (useful for audit trails and capacity calculations).
//
// Note: there is intentionally no "cancellation policy" here -- once admitted,
// the data covered by a reservation may already be in cache, and reclaiming
// only affects the lot's accounting record. Operators who need a soft-cancel
// before admission should use PATCH to bring expiration_time forward.
//
// @Summary Mark a lot as reclaimed
// @Description Records a reclamation event against the lot at the server's
// @Description current wall-clock time. The reclamation timestamp is always
// @Description stamped by the server and cannot be supplied by the client.
// @Tags lots
// @Accept json
// @Produce json
// @Param lotName path string true "Lot name"
// @Param body body ReclaimLotRequest false "Reclamation metadata"
// @Success 200 {object} ReclaimLotResponse
// @Failure 400 {object} server_structs.SimpleApiResp
// @Failure 401 {object} server_structs.SimpleApiResp
// @Failure 403 {object} server_structs.SimpleApiResp
// @Failure 500 {object} server_structs.SimpleApiResp
// @Router /api/v1.0/lots/{lotName}/reclaim [post]
func reclaimLot(ctx *gin.Context) {
	lotName := ctx.Param("lotName")
	if lotName == "" {
		abortWithErr(ctx, http.StatusBadRequest, "missing :lotName path parameter", nil)
		return
	}
	req := ReclaimLotRequest{}
	if ctx.Request.ContentLength > 0 {
		if err := ctx.ShouldBindJSON(&req); err != nil {
			abortWithErr(ctx, http.StatusBadRequest, "invalid request body", err)
			return
		}
	}
	res, ok := requireAuth(ctx, lotName, token_scopes.Lot_Reclaim)
	if !ok {
		return
	}
	// The server is the only entity that stamps the reclamation time.
	// Allowing the client to backdate or future-date this would let
	// any caller corrupt the audit trail.
	reclaimedAt := time.Now().UnixMilli()
	rows, err := ReclaimLot(lotName, reclaimedAt, req.Reason, res.caller)
	if err != nil {
		abortWithErr(ctx, http.StatusInternalServerError, "failed to reclaim lot", err)
		return
	}
	status := ReclaimStatusReclaimed
	if rows == 0 {
		status = ReclaimStatusAlreadyReclaimed
	}
	ctx.JSON(http.StatusOK, ReclaimLotResponse{
		LotName:       lotName,
		Status:        status,
		Reason:        req.Reason,
		ReclaimedAtMs: reclaimedAt,
	})
}

// getLotChildren handles GET /api/v1.0/lots/:lotName/children.
//
// @Summary List a lot's children
// @Tags lots
// @Produce json
// @Param lotName path string true "Lot name"
// @Param recursive query bool false "Include all descendants (default false)"
// @Success 200 {object} LotChildrenResponse
// @Failure 401 {object} server_structs.SimpleApiResp
// @Failure 403 {object} server_structs.SimpleApiResp
// @Failure 500 {object} server_structs.SimpleApiResp
// @Router /api/v1.0/lots/{lotName}/children [get]
func getLotChildren(ctx *gin.Context) {
	lotName := ctx.Param("lotName")
	if lotName == "" {
		abortWithErr(ctx, http.StatusBadRequest, "missing :lotName path parameter", nil)
		return
	}
	var q GetLotQuery
	if err := ctx.ShouldBindQuery(&q); err != nil {
		abortWithErr(ctx, http.StatusBadRequest, "invalid query parameters", err)
		return
	}
	if _, ok := requireAuth(ctx, lotName, token_scopes.Lot_Read); !ok {
		return
	}
	names, err := GetChildrenNames(lotName, q.Recursive, false)
	if err != nil {
		abortWithErr(ctx, http.StatusInternalServerError, "failed to enumerate children", err)
		return
	}
	ctx.JSON(http.StatusOK, LotChildrenResponse{LotName: lotName, Children: names})
}

// getLotUsage handles GET /api/v1.0/lots/:lotName/usage. By default all
// usage axes are reported; the caller may opt out via per-axis query params.
//
// @Summary Get a lot's usage statistics
// @Tags lots
// @Produce json
// @Param lotName path string true "Lot name"
// @Param dedicatedGB query bool false "Include dedicatedGB axis (default true)"
// @Param opportunisticGB query bool false "Include opportunisticGB axis (default true)"
// @Param totalGB query bool false "Include totalGB axis (default true)"
// @Param numObjects query bool false "Include numObjects axis (default true)"
// @Param gbBeingWritten query bool false "Include gbBeingWritten axis (default true)"
// @Param objectsBeingWritten query bool false "Include objectsBeingWritten axis (default true)"
// @Success 200 {object} LotUsageResponse
// @Failure 401 {object} server_structs.SimpleApiResp
// @Failure 403 {object} server_structs.SimpleApiResp
// @Failure 500 {object} server_structs.SimpleApiResp
// @Router /api/v1.0/lots/{lotName}/usage [get]
func getLotUsage(ctx *gin.Context) {
	lotName := ctx.Param("lotName")
	if lotName == "" {
		abortWithErr(ctx, http.StatusBadRequest, "missing :lotName path parameter", nil)
		return
	}
	if _, ok := requireAuth(ctx, lotName, token_scopes.Lot_Read); !ok {
		return
	}
	// Default-true per-axis flags: opt-out via ?dedicatedGB=false etc.
	axisOn := func(name string) *bool {
		v := true
		if raw := ctx.Query(name); raw == "false" {
			v = false
		}
		return &v
	}
	req := UsageRequest{
		LotName:             lotName,
		DedicatedGB:         axisOn("dedicatedGB"),
		OpportunisticGB:     axisOn("opportunisticGB"),
		TotalGB:             axisOn("totalGB"),
		NumObjects:          axisOn("numObjects"),
		GBBeingWritten:      axisOn("gbBeingWritten"),
		ObjectsBeingWritten: axisOn("objectsBeingWritten"),
	}
	usage, err := GetLotUsage(req)
	if err != nil {
		abortWithErr(ctx, http.StatusInternalServerError, "failed to fetch usage", err)
		return
	}
	ctx.JSON(http.StatusOK, projectLotUsage(usage))
}

// getLotPolicy handles GET /api/v1.0/lots/:lotName/policy. Returns the
// most-restrictive MPA across the lot and its ancestors.
//
// All axis flags are hard-coded to true: callers asking for "the policy"
// always want the complete picture, and the underlying lotman call returns
// a single struct with omitempty fields anyway, so per-axis opt-out adds
// no real value here. Contrast getLotUsage, where the per-axis flags
// translate into separate (potentially expensive) DB aggregations.
//
// @Summary Get a lot's effective (most-restrictive) policy attributes
// @Tags lots
// @Produce json
// @Param lotName path string true "Lot name"
// @Success 200 {object} LotPolicyResponse
// @Failure 401 {object} server_structs.SimpleApiResp
// @Failure 403 {object} server_structs.SimpleApiResp
// @Failure 500 {object} server_structs.SimpleApiResp
// @Router /api/v1.0/lots/{lotName}/policy [get]
func getLotPolicy(ctx *gin.Context) {
	lotName := ctx.Param("lotName")
	if lotName == "" {
		abortWithErr(ctx, http.StatusBadRequest, "missing :lotName path parameter", nil)
		return
	}
	if _, ok := requireAuth(ctx, lotName, token_scopes.Lot_Read); !ok {
		return
	}
	req := PolicyAttrsRequest{
		LotName:         lotName,
		DedicatedGB:     true,
		OpportunisticGB: true,
		MaxNumObjects:   true,
		CreationTime:    true,
		ExpirationTime:  true,
		DeletionTime:    true,
	}
	rmpa, err := GetPolicyAttributes(req)
	if err != nil {
		abortWithErr(ctx, http.StatusInternalServerError, "failed to fetch policy attributes", err)
		return
	}
	ctx.JSON(http.StatusOK, projectRestrictiveMPA(rmpa))
}

// listLotsByPath handles GET /api/v1.0/lots/by-path. Returns the lots
// that own (or contain) a given path during the requested time window.
//
// Authorization keys off the PATH (not "root"), so namespace owners can
// answer "what reservations cover my path?" without holding a federation-
// signed token.
//
// @Summary List reservations that cover a path
// @Tags lots
// @Produce json
// @Param path query string true "Path to look up"
// @Param recursive query bool false "Include lots whose paths are recursive descendants (default false)"
// @Param includeReclaimed query bool false "Include lots already marked reclaimed (default false)"
// @Param fromMs query integer false "Start of the time window (ms since epoch); 0 = now"
// @Param toMs query integer false "End of the time window (ms since epoch); 0 = fromMs+1"
// @Success 200 {array} Reservation
// @Failure 400 {object} server_structs.SimpleApiResp
// @Failure 401 {object} server_structs.SimpleApiResp
// @Failure 403 {object} server_structs.SimpleApiResp
// @Failure 500 {object} server_structs.SimpleApiResp
// @Router /api/v1.0/lots/by-path [get]
func listLotsByPath(ctx *gin.Context) {
	var q ListLotsByPathQuery
	if err := ctx.ShouldBindQuery(&q); err != nil {
		abortWithErr(ctx, http.StatusBadRequest, "invalid query parameters", err)
		return
	}
	if _, ok := requireAuthForPath(ctx, q.Path, token_scopes.Lot_Read); !ok {
		return
	}
	from, to := normalizeWindow(q.FromMs, q.ToMs)
	lots, err := GetLotsForPath(q.Path, q.Recursive, from, to, q.IncludeReclaimed)
	if err != nil {
		abortWithErr(ctx, http.StatusInternalServerError, "failed to enumerate lots for path", err)
		return
	}
	nowMs := time.Now().UnixMilli()
	out := make([]Reservation, len(lots))
	for i := range lots {
		out[i] = lotToReservation(&lots[i], nowMs)
	}
	ctx.JSON(http.StatusOK, out)
}

// normalizeWindow returns a non-empty (strictly increasing) [from, to)
// interval suitable for lotman: when callers send 0/0 (point query), we
// nudge to_ms by 1ms because lotman requires to_ms > from_ms strictly.
func normalizeWindow(from, to int64) (int64, int64) {
	if from == 0 {
		from = time.Now().UnixMilli()
	}
	if to <= from {
		to = from + 1
	}
	return from, to
}

// getAvailableCapacity handles GET /api/v1.0/lots/by-path/capacity. This
// endpoint is intentionally public (no auth): capacity headroom is needed
// by clients deciding whether to upload, and the response is restricted
// (by api_types.AvailableCapacity) to numeric capacity fields only -- it
// carries no owner-, lot-name- or path-identifying data.
//
// @Summary Get available capacity at a path
// @Tags lots
// @Produce json
// @Param path query string true "Path whose owning lot's children should be queried"
// @Param fromMs query integer false "Start of the window (ms since epoch); 0 = now"
// @Param toMs query integer false "End of the window (ms since epoch); 0 = fromMs+1"
// @Success 200 {object} AvailableCapacityResponse
// @Failure 400 {object} server_structs.SimpleApiResp
// @Failure 404 {object} server_structs.SimpleApiResp
// @Failure 500 {object} server_structs.SimpleApiResp
// @Router /api/v1.0/lots/by-path/capacity [get]
func getAvailableCapacity(ctx *gin.Context) {
	var q CapacityQuery
	if err := ctx.ShouldBindQuery(&q); err != nil {
		abortWithErr(ctx, http.StatusBadRequest, "invalid query parameters", err)
		return
	}
	from, to := normalizeWindow(q.FromMs, q.ToMs)
	// Resolve path -> owning lot, then ask for its children's headroom.
	lots, err := GetLotsForPath(q.Path, false, from, to, false)
	if err != nil {
		abortWithErr(ctx, http.StatusInternalServerError, "failed to resolve path to owning lot", err)
		return
	}
	if len(lots) == 0 {
		abortWithErr(ctx, http.StatusNotFound, "no lot covers the supplied path", nil)
		return
	}
	// The owning lot may be the synthetic "default" lot, which is itself a
	// rootly lot (a self-parent alongside "root"). Query its capacity
	// directly rather than redirecting to "root".
	parent := lots[0].LotName
	cap, err := GetAvailableCapacity(parent, from, to)
	if err != nil {
		abortWithErr(ctx, http.StatusInternalServerError, "failed to fetch available capacity", err)
		return
	}
	ctx.JSON(http.StatusOK, projectAvailableCapacity(cap))
}

// RegisterLotsAPI wires the /api/v1.0/lots/* surface onto router.
func RegisterLotsAPI(router *gin.RouterGroup) error {
	if router == nil {
		return errors.New("router is nil")
	}
	lots := router.Group("/api/v1.0/lots")
	lots.GET("", listLots)
	lots.POST("", createLot)
	lots.GET("/by-path", listLotsByPath)
	lots.GET("/by-path/capacity", getAvailableCapacity)
	lots.GET("/:lotName", getLot)
	lots.PATCH("/:lotName", patchLot)
	lots.DELETE("/:lotName", deleteLot)
	lots.POST("/:lotName/reclaim", reclaimLot)
	lots.GET("/:lotName/children", getLotChildren)
	lots.GET("/:lotName/usage", getLotUsage)
	lots.GET("/:lotName/policy", getLotPolicy)
	return nil
}
