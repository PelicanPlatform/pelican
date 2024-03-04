//go:build !windows && !darwin

/***************************************************************
*
* Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	// "github.com/pkg/errors"
	"github.com/lestrrat-go/jwx/v2/jwt"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/utils"
)

func uiCreateLot(ctx *gin.Context) {
	// Unmarshal the lot JSON from the incoming context
	extraInfo := ""
	var lot Lot
	err := ctx.BindJSON(&lot)
	if err != nil {
		log.Errorf("Error binding lot JSON: %v", err)
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Error binding incoming lot JSON: %v", err)})
		return
	}

	// Right now we assume a single path. The authorization scheme gets complicated quickly otherwise.
	if len(lot.Paths) > 1 {
		log.Errorf("error creating lot: Lot contains more than one path, which is not yet supported by Pelican")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Error creating lot: Lot contains more than one path, which is not yet supported by Pelican"})
	}

	if lot.Owner != "" {
		extraInfo += "NOTE: New lot owner fields are ignored. The owner will be set to the issuer of the token used to create the lot. "
	}
	if len(lot.Parents) > 0 {
		extraInfo += "NOTE: New lot parent fields are ignored. The parent will be determined by the namespace heirarchy associated with the lot's path. "
	}

	// TODO: Figure out the best way to inform the user that we ignore any owner or parent they set, because we handle that internally.

	token := utils.GetAuthzEscaped(ctx)
	if token == "" {
		log.Debugln("No token provided in request")
		ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "No token provided in request"})
		return
	}

	// TODO: Since VerifyNewLotToken has a few side effects (like modifying the underlying lot obj), it might also
	// need to handle a case where the lot for /foo/bar/baz is created before /foo/bar. Currently, if these are the
	// first two lots we create with this endpoint, then both will be set to have "root" as a parent, and we'd like
	// /foo/bar/baz to be modified to have /foo/bar as a parent. This gets complicated, so let's punt on it for now.
	ok, err := VerifyNewLotToken(&lot, token)

	// TODO: Distinguish between true errors and unauthorized errors
	if err != nil {
		log.Debugln("Error verifying token: ", err)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Error verifying token: %v", err)})
		return
	}
	if !ok {
		log.Debugln("Token verification failed")
		ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Token does not appear to have necessary authorization to create a lot"})
		return
	}

	// For creating lots, the Lotman caller must be set to an owner of a parent. Since the incoming token
	// was presumably signed by someone with the necessary permissions, we can use the token's issuer as the
	// Lotman caller.
	tok, err := jwt.Parse([]byte(token), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		log.Debugf("Failed to parse token while determining Lotman Caller: %v", err)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse token while determining Lotman Caller"})
	}
	caller := tok.Issuer()

	err = CreateLot(&lot, caller)
	if err != nil {
		log.Errorf("Error creating lot: %v", err)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Error creating lot: %v", err)})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"status": "success" + extraInfo})
}

func uiGetLotJSON(ctx *gin.Context) {
	lotName := ctx.Query("lotName")
	recursiveStr := ctx.Query("recursive")
	var recursive bool
	var err error
	if recursiveStr != "" {
		recursive, err = strconv.ParseBool(recursiveStr)
		if err != nil {
			log.Errorf("Error parsing recursive query param: %v", err)
			ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Error parsing recursive query param: %v", err)})
			return
		}
	}

	lot, err := GetLot(lotName, recursive)
	if err != nil {
		log.Errorf("Error fetching lot: %v", err)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Error fetching lot: %v", err)})
		return
	}

	ctx.JSON(http.StatusOK, lot)
}

// NOTE: For now we'll allow updates to parents, paths and MPAs. We'll ignore owner fields, since Pelican figures out who
// owns things internally
func uiUpdateLot(ctx *gin.Context) {
	// Unmarshal the lot JSON from the incoming context
	extraInfo := " "
	var lotUpdate LotUpdate
	err := ctx.BindJSON(&lotUpdate)
	if err != nil {
		log.Errorf("Error binding lot JSON: %v", err)
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Error binding incoming lot JSON: %v", err)})
		return
	}

	// Right now we assume a single path. The authorization scheme gets complicated quickly otherwise.
	if len(*lotUpdate.Paths) > 1 {
		log.Errorf("error updating lot: The update contains more than one path, which is not yet supported by Pelican")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Error updating lot: The update contains more than one path, which is not yet supported by Pelican"})
	}

	if lotUpdate.Owner != nil {
		extraInfo += "NOTE: Lot owner fields are ignored. The owner will be set to the issuer of the token used to create the lot. "
		lotUpdate.Owner = nil
	}

	// TODO: I thought about this a bit, and wasn't sure how to handle the case where we have a path update. One of two scenarios
	// might be true.
	// 1: The new path is already tied to another lot. If this is the case, then we shouldn't be trying to add that path to this lot
	// because LotMan assumes a path can be held by only one lot (hierarchical ownership not withstanding).
	// 2: The new path is not tied to another lot. In this case, what we should really do is create a new lot for that namespace, assuming
	// one exists. But then why not create a new lot?
	// Thus, until we've sorted out multi-path lots, we should probably just error out in both of these cases. An adminstrator at the cache
	// can get access to the system and update things however they choose anyway (albeit that means writing C to do it).
	if lotUpdate.Paths != nil {
		extraInfo += "NOTE: Lot update path fields are ignored. Pelican does not yet support this feature. "
		lotUpdate.Paths = nil
	}

	token := utils.GetAuthzEscaped(ctx)
	if token == "" {
		log.Debugln("No token provided in request")
		ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "No token provided in request"})
		return
	}

	ok, err := VerifyUpdateLotToken(&lotUpdate, token)

	// TODO: Distinguish between true errors and unauthorized errors
	if err != nil {
		log.Debugln("Error verifying token: ", err)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Error verifying token: %v", err)})
		return
	}
	if !ok {
		log.Debugln("Token verification failed")
		ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Token does not appear to have necessary authorization to delete a lot"})
		return
	}

	// For updating lots, the Lotman caller must be set to an owner of a parent. Since the incoming token
	// was presumably signed by someone with the necessary permissions, we can use the token's issuer as the
	// Lotman caller.
	tok, err := jwt.Parse([]byte(token), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		log.Debugf("Failed to parse token while determining Lotman Caller: %v", err)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse token while determining Lotman Caller"})
	}

	caller := tok.Issuer()
	err = UpdateLot(&lotUpdate, caller)
	if err != nil {
		log.Errorf("Error updating lot: %v", err)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Error updating lot: %v", err)})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"status": "success" + extraInfo})
}

func uiDeleteLot(ctx *gin.Context) {
	lotName := ctx.Query("lotName")
	if lotName == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "No lot name provided in URL query param 'lotName'"})
		return
	}

	token := utils.GetAuthzEscaped(ctx)
	if token == "" {
		log.Debugln("No token provided in request")
		ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "No token provided in request"})
		return
	}
	ok, err := VerifyDeleteLotToken(lotName, token)

	// TODO: Distinguish between true errors and unauthorized errors
	if err != nil {
		log.Debugln("Error verifying token: ", err)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Error verifying token: %v", err)})
		return
	}
	if !ok {
		log.Debugln("Token verification failed")
		ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Token does not appear to have necessary authorization to delete the lot"})
		return
	}

	// For creating lots, the Lotman caller must be set to an owner of a parent. Since the incoming token
	// was presumably signed by someone with the necessary permissions, we can use the token's issuer as the
	// Lotman caller.
	tok, err := jwt.Parse([]byte(token), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		log.Debugf("Failed to parse token while determining Lotman Caller: %v", err)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse token while determining Lotman Caller"})
	}
	caller := tok.Issuer()

	err = DeleteLotsRecursive(lotName, caller)
	if err != nil {
		log.Errorf("Error deleting lot: %v", err)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Error deleting lot: %v", err)})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"status": "success"})
}

func RegisterLotman(ctx context.Context, router *gin.RouterGroup) {
	router.GET("/api/v1.0/lotman/getLotJSON", uiGetLotJSON)
	router.PUT("/api/v1.0/lotman/createLot", uiCreateLot)
	router.DELETE("/api/v1.0/lotman/deleteLotsRecursive", uiDeleteLot)
	router.PUT("/api/v1.0/lotman/updateLot", uiUpdateLot)
}
