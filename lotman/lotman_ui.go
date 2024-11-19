//go:build lotman && linux && !ppc64le

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
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unsafe"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils"
)

type LotAction string

var (
	LotUpdateAction LotAction = "modify"
	LotDeleteAction LotAction = "delete"
)

// Given a token and a list of authorized callers, check that the token is signed by one of the authorized callers. Return
// a pointer to the parsed token.
func tokenSignedByAuthorizedCaller(strToken string, authorizedCallers *[]string) (bool, *jwt.Token, error) {
	ownerFound := false
	var tok jwt.Token
	for _, owner := range *authorizedCallers {
		kSet, err := server_utils.GetJWKSFromIssUrl(owner)
		if err != nil {
			log.Debugf("Error getting JWKS for owner %s: %v", owner, err)
			continue
		}
		tok, err = jwt.Parse([]byte(strToken), jwt.WithKeySet(*kSet), jwt.WithValidate(true))
		if err != nil {
			log.Debugf("Token verification failed with owner %s: %v -- skipping", owner, err)
			continue
		}
		ownerFound = true
		break
	}

	if !ownerFound {
		return false, nil, errors.New("token not signed by any of the owners of any parent lot")
	}

	return true, &tok, nil
}

// Verify that a token received is a valid token. Upon verification, we set the lot's parents/owner to the
// appropriate values. Returns true if the token is valid, false otherwise.
func VerifyNewLotToken(lot *Lot, strToken string) (bool, error) {
	tokenApproved := false

	// Get the path associated with the lot (right now we assume/enforce a single path) and try
	// to deduce a namespace prefix from that. We'll use that namespace prefix's issuer as the
	// lot's owner field (which is the data owner). If there is no associated isuer, we assign
	// ownership to the federation

	path := ((lot.Paths)[0]).Path
	log.Debugf("Attempting to add lot for path: %s", path)
	errMsg := make([]byte, 2048)
	lots := unsafe.Pointer(nil)
	// Pass a pointer to the first element of the slice to the C++ function.
	ret := LotmanGetLotsFromDir(path, false, &lots, &errMsg)
	if ret != 0 {
		trimBuf(&errMsg)
		return false, errors.Errorf("Error getting lot JSON: %s", string(errMsg))
	}

	goLots := cArrToGoArr(&lots)

	// Check if goOut[0] is "default". Lotman should ALWAYS put something in this array. If it's empty, we have a problem.
	if goLots[0] == "default" {
		// We'll assign to the root lot. However, be careful here because we make an assumption -- under the hood,
		// Lotman will return "default" if there's no other lot, or if the actual path is in some way assigned to
		// the default lot. When we assign to parent to root here, we're assuming the former. This implies we should stay
		// away from assigning paths to the default lot.
		lot.Parents = []string{"root"}
	} else {
		// We found a different logical parent
		lot.Parents = goLots
	}

	var tok jwt.Token
	if len(lot.Parents) != 0 && lot.Parents[0] == "root" {
		// We check that the token is signed by the federation
		// First check for discovery URL and then for director URL, both of which should host the federation's pubkey
		issuerUrl, err := getFederationIssuer()
		if err != nil {
			return false, err
		}

		kSet, err := server_utils.GetJWKSFromIssUrl(issuerUrl)
		if err != nil {
			return false, errors.Wrap(err, "Error getting JWKS from issuer URL")
		}

		tok, err = jwt.Parse([]byte(strToken), jwt.WithKeySet(*kSet), jwt.WithValidate(true))
		if err != nil {
			return false, errors.Wrap(err, "Error parsing token")
		}
	} else {

		// Use a map to handle deduplication of owners list
		ownersSet := make(map[string]struct{})
		for _, parent := range lot.Parents {
			cOwners := unsafe.Pointer(nil)
			LotmanGetLotOwners(parent, true, &cOwners, &errMsg)
			if ret != 0 {
				trimBuf(&errMsg)
				return false, errors.Errorf("Error getting lot JSON: %s", string(errMsg))
			}

			for _, owner := range cArrToGoArr(&cOwners) {
				ownersSet[owner] = struct{}{}
			}
		}

		ownerFound := false
		for owner := range ownersSet {
			kSet, err := server_utils.GetJWKSFromIssUrl(owner)

			// Print the kSet as a string for debugging
			kSetStr, _ := json.Marshal(kSet)
			log.Debugf("JWKS for owner %s: %s", owner, string(kSetStr))
			if err != nil {
				log.Debugf("Error getting JWKS for owner %s: %v", owner, err)
				continue
			}
			tok, err = jwt.Parse([]byte(strToken), jwt.WithKeySet(*kSet), jwt.WithValidate(true))
			if err != nil {
				log.Debugf("Token verification failed with owner %s: %v -- skipping", owner, err)
				continue
			}
			ownerFound = true
			break
		}

		if !ownerFound {
			return false, errors.New("token not signed by any of the owners of any parent lot")
		}
	}

	// We've determined the token is signed by someone we like, now to check that it has the correct lot.create permission!
	scope_any, present := tok.Get("scope")
	if !present {
		return false, errors.New("No scope claim in token")
	}
	scope, ok := scope_any.(string)
	if !ok {
		return false, errors.New("scope claim in token is not string-valued")
	}
	scopes := strings.Split(scope, " ")
	for _, scope := range scopes {
		if scope == token_scopes.Lot_Create.String() {
			tokenApproved = true
			break
		}
	}

	if !tokenApproved {
		return false, errors.New("The token was correctly signed but did not possess the necessary lot.create scope")
	}

	// At this point, we have a good token, now we need to get the appropriate owner for the lot.
	// To do this, we get a namespace from the path and then get the issuer for that namespace. If no
	// namespace exists, we'll assign ownership to the federation.

	// TODO: Once we have the new Director endpoint that returns a namespace for a given path, we'll use that
	// and cut out a lot of this cruft

	// Get the namespace by querying the director and checking the headers
	errMsgPrefix := "the provided token is acceptible, but no owner could be determined because "

	fedInfo, err := config.GetFederation(context.Background())
	if err != nil {
		return false, errors.Wrap(err, errMsgPrefix+"the federation information could not be retrieved")
	}
	directorUrlStr := fedInfo.DirectorEndpoint
	if directorUrlStr == "" {
		return false, errors.New(errMsgPrefix + "the federation director URL is not set")
	}
	directorUrl, err := url.Parse(directorUrlStr)
	if err != nil {
		return false, errors.Wrap(err, errMsgPrefix+"the federation director URL is not a valid URL")
	}

	directorUrl.Path, err = url.JoinPath("/api/v1.0/director/object", path)
	if err != nil {
		return false, errors.Wrap(err, errMsgPrefix+"the director's object path could not be constructed")
	}

	// Get the namespace by querying the director and checking the headers. The client should NOT
	// follow the redirect
	httpClient := &http.Client{
		Transport: config.GetTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", directorUrl.String(), nil)
	if err != nil {
		return false, errors.Wrap(err, errMsgPrefix+"the director request could not be created")
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, errors.Wrapf(err, errMsgPrefix+"the director couldn't be queried for path %s", path)
	}

	// Check the response code, make sure it's not in the error ranges (400-500)
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return false, errors.Errorf(errMsgPrefix+"the director returned a bad status for path %s: %s", path, resp.Status)
	}

	// Get the namespace from the X-Pelican-Namespace header
	namespaceHeader := resp.Header.Values("X-Pelican-Namespace")
	xPelicanNamespaceMap := utils.HeaderParser(namespaceHeader[0])
	namespace := xPelicanNamespaceMap["namespace"]

	// Get the issuer URL for that namespace
	nsIssuerUrl, err := server_utils.GetNSIssuerURL(namespace)
	if err != nil {
		return false, errors.Wrapf(err, errMsgPrefix+"no issuer could be found for namespace %s", namespace)
	}
	lot.Owner = nsIssuerUrl

	return true, nil
}

// Actions that modify lots themselves (be it delete or modify) require the same authorization. This function
// verifies the token against the requested action.
func VerifyLotModTokens(lotName string, strToken string, action LotAction) (bool, error) {
	// Get all parents of the lot, which we use to determine owners who can modify the lot itself (as opposed
	// to the data in the lot).
	tokenApproved := false

	log.Debugf("Attempting to %s lot %s", action, lotName)
	authzCallers, err := GetAuthorizedCallers(lotName)
	if err != nil {
		return false, errors.Wrap(err, "Error getting authorized callers")
	}

	ownerSigned, tok, err := tokenSignedByAuthorizedCaller(strToken, authzCallers)
	if err != nil {
		return false, errors.Wrap(err, "Error verifying token is appropriately signed")
	}
	if !ownerSigned {
		return false, errors.New("Token not signed by any of the owners of any parent lot")
	}

	// We've determined the token is signed by someone we like, now to check that it has the correct scope!
	scope_any, present := (*tok).Get("scope")
	if !present {
		return false, errors.New("no scope claim in token")
	}
	scope, ok := scope_any.(string)
	if !ok {
		return false, errors.New("scope claim in token is not string-valued")
	}
	scopes := strings.Split(scope, " ")
	for _, scope := range scopes {
		switch action {
		case LotUpdateAction:
			if scope == token_scopes.Lot_Modify.String() {
				tokenApproved = true
				break
			}
		case LotDeleteAction:
			if scope == token_scopes.Lot_Delete.String() {
				tokenApproved = true
				break
			}
		default:
			return false, errors.New(fmt.Sprintf("invalid lot action: %s", action))
		}
	}

	if !tokenApproved {
		return false, errors.New(fmt.Sprintf("The token was correctly signed, but does not have permission to %s the lot", action))
	}

	return true, nil

}

// The function Gin routes to when the CreateLot endpoint is hit.
func uiCreateLot(ctx *gin.Context) {
	// Unmarshal the lot JSON from the incoming context
	extraInfo := ""
	var lot Lot
	err := ctx.BindJSON(&lot)
	if err != nil {
		log.Errorf("Error binding lot JSON: %v", err)
		ctx.AbortWithStatusJSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Error binding incoming lot JSON: %v", err),
		})
		return
	}

	// Right now we assume a single path. The authorization scheme gets complicated quickly otherwise.
	if len(lot.Paths) > 1 {
		log.Errorf("error creating lot: Lot contains more than one path, which is not yet supported by Pelican")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Error creating lot: Lot contains more than one path, which is not yet supported by Pelican",
		})
	}

	if lot.Owner != "" {
		extraInfo += "NOTE: New lot owner fields are ignored. The owner will be set to the issuer of the token used to create the lot. "
	}
	if len(lot.Parents) > 0 {
		extraInfo += "NOTE: New lot parent fields are ignored. The parent will be determined by the namespace heirarchy associated with the lot's path. "
	}

	// TODO: Figure out the best way to inform the user that we ignore any owner or parent they set, because we handle that internally.

	token := token.GetAuthzEscaped(ctx)
	if token == "" {
		log.Debugln("No token provided in request")
		ctx.AbortWithStatusJSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "No token provided in request",
		})
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
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Error verifying token: %v", err),
		})
		return
	}
	if !ok {
		log.Debugln("Token verification failed")
		ctx.AbortWithStatusJSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Token does not appear to have necessary authorization to create a lot",
		})
		return
	}

	// For creating lots, the Lotman caller must be set to an owner of a parent. Since the incoming token
	// was presumably signed by someone with the necessary permissions, we can use the token's issuer as the
	// Lotman caller.
	tok, err := jwt.Parse([]byte(token), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		log.Debugf("Failed to parse token while determining Lotman Caller: %v", err)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to parse token while determining Lotman Caller",
		})
	}
	caller := tok.Issuer()

	err = CreateLot(&lot, caller)
	if err != nil {
		log.Errorf("Error creating lot: %v", err)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Error creating lot: %v", err),
		})
		return
	}

	ctx.JSON(http.StatusOK, server_structs.SimpleApiResp{
		Status: server_structs.RespOK,
		Msg:    fmt.Sprint("success: ", extraInfo),
	})
}

// The function Gin routes to when the GetLotJSON endpoint is hit.
func uiGetLotJSON(ctx *gin.Context) {
	lotName := ctx.Query("lotName")
	recursiveStr := ctx.Query("recursive")
	var recursive bool
	var err error
	if recursiveStr != "" {
		recursive, err = strconv.ParseBool(recursiveStr)
		if err != nil {
			log.Errorf("Error parsing recursive query param: %v", err)
			ctx.AbortWithStatusJSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Error parsing recursive query param: %v", err),
			})
			return
		}
	}

	lot, err := GetLot(lotName, recursive)
	if err != nil {
		log.Errorf("Error fetching lot: %v", err)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Error fetching lot: %v", err),
		})
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
		ctx.AbortWithStatusJSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Error binding incoming lot JSON: %v", err),
		})
		return
	}

	// Right now we assume a single path. The authorization scheme gets complicated quickly otherwise.
	if len(*lotUpdate.Paths) > 1 {
		log.Errorf("error updating lot: The update contains more than one path, which is not yet supported by Pelican")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Error updating lot: The update contains more than one path, which is not yet supported by Pelican",
		})
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

	token := token.GetAuthzEscaped(ctx)
	if token == "" {
		log.Debugln("No token provided in request")
		ctx.AbortWithStatusJSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "No token provided in request",
		})
		return
	}

	ok, err := VerifyLotModTokens(lotUpdate.LotName, token, LotUpdateAction)

	// TODO: Distinguish between true errors and unauthorized errors
	if err != nil {
		log.Debugln("Error verifying token: ", err)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Error verifying token: %v", err),
		})
		return
	}
	if !ok {
		log.Debugln("Token verification failed")
		ctx.AbortWithStatusJSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Token does not appear to have necessary authorization to delete a lot",
		})
		return
	}

	// For updating lots, the Lotman caller must be set to an owner of a parent. Since the incoming token
	// was presumably signed by someone with the necessary permissions, we can use the token's issuer as the
	// Lotman caller.
	tok, err := jwt.Parse([]byte(token), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		log.Debugf("Failed to parse token while determining Lotman Caller: %v", err)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to parse token while determining Lotman Caller",
		})
	}

	caller := tok.Issuer()
	err = UpdateLot(&lotUpdate, caller)
	if err != nil {
		log.Errorf("Error updating lot: %v", err)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Error updating lot: %v", err),
		})
		return
	}

	ctx.JSON(http.StatusOK, server_structs.SimpleApiResp{
		Status: server_structs.RespOK,
		Msg:    fmt.Sprint("success: ", extraInfo),
	})
}

// The function Gin routes to when the DeleteLotsRecursive endpoint is hit.
func uiDeleteLot(ctx *gin.Context) {
	lotName := ctx.Query("lotName")
	if lotName == "" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "No lot name provided in URL query param 'lotName'",
		})
		return
	}

	token := token.GetAuthzEscaped(ctx)
	if token == "" {
		log.Debugln("No token provided in request")
		ctx.AbortWithStatusJSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "No token provided in request",
		})
		return
	}

	ok, err := VerifyLotModTokens(lotName, token, LotDeleteAction)

	// TODO: Distinguish between true errors and unauthorized errors
	if err != nil {
		log.Debugln("Error verifying token: ", err)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Error verifying token: %v", err),
		})
		return
	}
	if !ok {
		log.Debugln("Token verification failed")
		ctx.AbortWithStatusJSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Token does not appear to have necessary authorization to delete the lot",
		})
		return
	}

	// For creating lots, the Lotman caller must be set to an owner of a parent. Since the incoming token
	// was presumably signed by someone with the necessary permissions, we can use the token's issuer as the
	// Lotman caller.
	tok, err := jwt.Parse([]byte(token), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		log.Debugf("Failed to parse token while determining Lotman Caller: %v", err)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to parse token while determining Lotman Caller",
		})
	}
	caller := tok.Issuer()

	err = DeleteLotsRecursive(lotName, caller)
	if err != nil {
		log.Errorf("Error deleting lot: %v", err)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Error deleting lot: %v", err),
		})
		return
	}

	ctx.JSON(http.StatusOK, server_structs.SimpleApiResp{
		Status: server_structs.RespOK,
		Msg:    "success",
	})
}

func RegisterLotman(ctx context.Context, router *gin.RouterGroup) {
	router.GET("/api/v1.0/lotman/getLotJSON", uiGetLotJSON)
	router.PUT("/api/v1.0/lotman/createLot", uiCreateLot)
	router.DELETE("/api/v1.0/lotman/deleteLotsRecursive", uiDeleteLot)
	router.PUT("/api/v1.0/lotman/updateLot", uiUpdateLot)
}
