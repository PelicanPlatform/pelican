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

package registry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/utils"
	"github.com/pelicanplatform/pelican/web_ui"
	log "github.com/sirupsen/logrus"
)

type (
	registrationFieldType string

	registrationFieldOption struct {
		Name string `mapstructure:"name" json:"name"`
		ID   string `mapstructure:"id" json:"id"`
	}
	registrationField struct {
		Name          string                    `json:"name"`
		DisplayedName string                    `json:"displayed_name"`
		Type          registrationFieldType     `json:"type"`
		Required      bool                      `json:"required"`
		Options       []registrationFieldOption `json:"options"`
		Description   string                    `json:"description"`
		OptionsUrl    string                    `json:"-"` // Internal field to keep track of Urls
	}

	listNamespaceRequest struct {
		ServerType string `form:"server_type"`
		Status     string `form:"status"`
	}

	listNamespacesForUserRequest struct {
		Status string `form:"status"`
	}
)

var registrationFields []registrationField

const (
	String   registrationFieldType = "string"
	Int      registrationFieldType = "int"
	Boolean  registrationFieldType = "bool"
	Enum     registrationFieldType = "enum"
	DateTime registrationFieldType = "datetime"
)

func init() {
	registrationFields = make([]registrationField, 0)
	registrationFields = append(registrationFields, populateRegistrationFields("", Namespace{})...)
}

// Populate registrationFields array to provide available namespace registration fields
// for UI to render registration form
func populateRegistrationFields(prefix string, data interface{}) []registrationField {
	var fields []registrationField

	val := reflect.ValueOf(data)
	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		field := typ.Field(i)

		// Check for the "post" tag, it can be "exlude" or "required"
		if tag := field.Tag.Get("post"); tag == "exclude" {
			continue
		}

		name := ""
		if prefix != "" {
			name += prefix + "."
		}
		// If the field has a json tag. Use the name from json tag
		tempName := field.Name
		jsonTag := field.Tag.Get("json")
		if jsonTag != "" {
			splitJson := strings.Split(jsonTag, ",")[0]
			if splitJson != "-" {
				tempName = splitJson
			} else {
				// `json:"-"` means this field should be removed from any marshaling
				continue
			}
		}

		regField := registrationField{
			Name:          name + tempName,
			DisplayedName: utils.SnakeCaseToHumanReadable(tempName),
			Required:      strings.Contains(field.Tag.Get("validate"), "required"),
		}

		switch field.Type.Kind() {
		case reflect.Int:
			regField.Type = Int
			fields = append(fields, regField)
		case reflect.String:
			regField.Type = String
			fields = append(fields, regField)
		case reflect.Struct:
			// Check if the struct is of type time.Time
			if field.Type == reflect.TypeOf(time.Time{}) {
				regField.Type = DateTime
				fields = append(fields, regField)
				break
			}
			// If it's AdminMetadata, add prefix and recursively call to parse fields
			if field.Type == reflect.TypeOf(AdminMetadata{}) {
				existing_prefix := ""
				if prefix != "" {
					existing_prefix = prefix + "."
				}
				fields = append(fields, populateRegistrationFields(existing_prefix+"admin_metadata", AdminMetadata{})...)
			}
		}

		if field.Type == reflect.TypeOf(RegistrationStatus("")) {
			regField.Type = Enum
			options := make([]registrationFieldOption, 3)
			options[0] = registrationFieldOption{Name: Pending.String(), ID: Pending.LowerString()}
			options[1] = registrationFieldOption{Name: Approved.String(), ID: Approved.LowerString()}
			options[2] = registrationFieldOption{Name: Denied.String(), ID: Denied.LowerString()}
			regField.Options = options
			fields = append(fields, regField)
		} else {
			// Skip the field if it's not in the types listed above
			continue
		}
	}
	return fields
}

// List all namespaces in the registry.
// For authenticated users, it returns all namespaces.
// For non-authenticated users, it returns namespaces with AdminMetadata.Status = Approved
//
// Query against server_type, status
//
// GET /namespaces
func listNamespaces(ctx *gin.Context) {
	// Directly call GetUser as we want this endpoint to also be able to serve unauthed users
	user, err := web_ui.GetUser(ctx)
	if err != nil {
		log.Error("Failed to check user login status: ", err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to check user login status"})
		return
	}
	ctx.Set("User", user)
	isAuthed := user != ""
	queryParams := listNamespaceRequest{}
	if err := ctx.ShouldBindQuery(&queryParams); err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Invalid query parameters"})
		return
	}

	// For unauthed user with non-empty Status query != Approved, return 403
	if !isAuthed && queryParams.Status != "" && queryParams.Status != Approved.String() {
		ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "You don't have permission to filter non-approved namespace registrations"})
		return
	}

	// Filter ns by server type
	if queryParams.ServerType != "" && queryParams.ServerType != string(OriginType) && queryParams.ServerType != string(CacheType) {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Invalid server type: %s", queryParams.ServerType)})
		return
	}

	filterNs := Namespace{}

	// For authenticated users, it returns all namespaces.
	// For unauthenticated users, it returns namespaces with AdminMetadata.Status = Approved
	if isAuthed {
		if queryParams.Status != "" {
			if IsValidRegStatus(queryParams.Status) {
				filterNs.AdminMetadata.Status = RegistrationStatus(queryParams.Status)
			} else {
				ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
					Status: server_structs.RespFailed,
					Msg:    fmt.Sprintf("Invalid query parameters %s: status must be one of  'Pending', 'Approved', 'Denied', 'Unknown'", queryParams.Status)})
			}
		}
	} else {
		filterNs.AdminMetadata.Status = Approved
	}

	namespaces, err := getNamespacesByFilter(filterNs, ServerType(queryParams.ServerType))
	if err != nil {
		log.Error("Failed to get namespaces by server type: ", err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Server encountered an error trying to list namespaces"})
		return
	}
	nssWOPubkey := excludePubKey(namespaces)
	ctx.JSON(http.StatusOK, nssWOPubkey)
}

// List namespaces for the currently authenticated user
//
// # Query against status
//
// GET /namespaces/user
func listNamespacesForUser(ctx *gin.Context) {
	user := ctx.GetString("User")
	if user == "" {
		ctx.JSON(http.StatusUnauthorized, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "You need to login to perform this action"})
		return
	}
	queryParams := listNamespacesForUserRequest{}
	if err := ctx.ShouldBindQuery(&queryParams); err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Invalid query parameters: %v", err)})
		return
	}

	filterNs := Namespace{AdminMetadata: AdminMetadata{UserID: user}}

	if queryParams.Status != "" {
		if IsValidRegStatus(queryParams.Status) {
			filterNs.AdminMetadata.Status = RegistrationStatus(queryParams.Status)
		} else {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Invalid query parameters %s: status must be one of 'Pending', 'Approved', 'Denied', 'Unknown'", queryParams.Status)})
		}
	}

	namespaces, err := getNamespacesByFilter(filterNs, "")
	if err != nil {
		log.Error("Error getting namespaces for user ", user)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Error getting namespaces by user ID"})
		return
	}
	ctx.JSON(http.StatusOK, namespaces)
}

func getNamespaceRegFields(ctx *gin.Context) {
	for idx, field := range registrationFields {
		if field.OptionsUrl != "" {
			options, err := getCachedOptions(field.OptionsUrl)
			if err != nil {
				log.Errorf("failed to get options from optionsUrl %s for key %s", field.OptionsUrl, field.Name)
				ctx.JSON(http.StatusInternalServerError,
					server_structs.SimpleApiResp{
						Status: server_structs.RespFailed,
						Msg:    fmt.Sprintf("failed to get options from optionsUrl %s for key %s", field.OptionsUrl, field.Name),
					})
			}
			registrationFields[idx].Options = options
		}
	}
	ctx.JSON(http.StatusOK, registrationFields)
}

// Create a new namespace registration or update existing namespace registration.
//
// For update, only admin-user can update an existing registration if it's been approved already.
//
// One caveat in updating is that if the namespace to update was a legacy registration, i.e. It doesn't have
// AdminMetaData populated, an update __will__ populate the AdminMetaData field and update
// AdminMetaData based on user input. However, internal fields are still preserved.
//
// POST /namespaces
// PUT /namespaces/:id
func createUpdateNamespace(ctx *gin.Context, isUpdate bool) {
	user := ctx.GetString("User")
	id := 0 // namespace ID when doing update, will be populated later
	if user == "" {
		ctx.JSON(http.StatusUnauthorized, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "You need to login to perform this action"})
		return
	}
	if isUpdate {
		idStr := ctx.Param("id")
		var err error
		id, err = strconv.Atoi(idStr)
		if err != nil || id <= 0 {
			// Handle the error if id is not a valid integer
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Invalid ID format. ID must a positive integer"})
			return
		}
	}

	ns := Namespace{}
	if ctx.ShouldBindJSON(&ns) != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Invalid create or update namespace request"})
		return
	}
	// Assign ID from path param because the request data doesn't have ID set
	ns.ID = id
	// Basic validation (type, required, etc)
	errs := config.GetValidate().Struct(ns)
	if errs != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    errs.Error()})
		return
	}
	// Check that Prefix is a valid prefix
	updated_prefix, err := validatePrefix(ns.Prefix)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Error: Field validation for prefix failed: %v", err)})
		return
	}
	ns.Prefix = updated_prefix

	if !isUpdate {
		// Check if prefix exists before doing anything else. Skip check if it's update operation
		exists, err := namespaceExistsByPrefix(ns.Prefix)
		if err != nil {
			log.Errorf("Failed to check if namespace already exists: %v", err)
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Server encountered an error checking if namespace already exists"})
			return
		}
		if exists {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("The prefix %s is already registered", ns.Prefix)})
			return
		}
	}
	// Check if pubKey is a valid JWK
	pubkey, err := validateJwks(ns.Pubkey)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Error: Field validation for pubkey failed: %v", err)})
		return
	}

	// Check if the parent or child path along the prefix has been registered
	inTopo, topoNss, valErr, sysErr := validateKeyChaining(ns.Prefix, pubkey)
	if valErr != nil {
		log.Errorln("Bad prefix when validating key chaining", valErr)
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    valErr.Error()})
		return
	}
	if sysErr != nil {
		log.Errorln("Error validating key chaining", sysErr)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    sysErr.Error()})
		return
	}

	if validInst, err := validateInstitution(ns.AdminMetadata.Institution); !validInst {
		if err != nil {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Error validating institution: %v", err)})
			return
		}
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Institution \"%s\" is not in the list of available institutions to register.", ns.AdminMetadata.Institution)})
		return
	}

	if validCF, err := validateCustomFields(ns.CustomFields); !validCF {
		if !validCF && err != nil {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Validation failed: %v", err)})
			return
		} else if !validCF {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Invalid custom fields without a validation error returned"})
			return
		}
	}

	if !isUpdate { // Create
		ns.AdminMetadata.UserID = user
		// Overwrite status to Pending to filter malicious request
		ns.AdminMetadata.Status = Pending
		if inTopo {
			ns.AdminMetadata.Description = fmt.Sprintf("[ Attention: A superspace or subspace of this prefix exists in OSDF topology: %s ] ", GetTopoPrefixString(topoNss))
		}
		if err := AddNamespace(&ns); err != nil {
			log.Errorf("Failed to insert namespace with id %d. %v", ns.ID, err)
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Fail to insert namespace"})
			return
		}
		if inTopo {
			ctx.JSON(http.StatusOK,
				server_structs.SimpleApiResp{
					Status: server_structs.RespOK,
					Msg:    fmt.Sprintf("Prefix %s successfully registered. Note that there is an existing superspace or subspace of the namespace in the OSDF topology: %s. The registry admin will review your request and approve your namespace if this is expected.", ns.Prefix, GetTopoPrefixString(topoNss)),
				})
		} else {
			ctx.JSON(http.StatusOK,
				server_structs.SimpleApiResp{
					Status: server_structs.RespOK,
					Msg:    fmt.Sprintf("Prefix %s successfully registered", ns.Prefix),
				})
		}
	} else { // Update
		// First check if the namespace exists
		exists, err := namespaceExistsById(ns.ID)
		if err != nil {
			log.Error("Failed to get namespace by ID:", err)
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Fail to find if namespace exists"})
			return
		}

		if !exists { // Return 404 is the namespace does not exists
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Can't update namespace: namespace not found"})
			return
		}

		// Then check if the user has previlege to update
		isAdmin, _ := web_ui.CheckAdmin(user)
		if !isAdmin { // Not admin, need to check if the namespace belongs to the user
			found, err := namespaceBelongsToUserId(ns.ID, user)
			if err != nil {
				log.Error("Error checking if namespace belongs to the user: ", err)
				ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
					Status: server_structs.RespFailed,
					Msg:    "Error checking if namespace belongs to the user"})
				return
			}
			if !found {
				log.Errorf("Namespace not found for id: %d", ns.ID)
				ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
					Status: server_structs.RespFailed,
					Msg:    "Namespace not found. Check the id or if you own the namespace"})
				return
			}
			existingStatus, err := getNamespaceStatusById(ns.ID)
			if err != nil {
				log.Error("Error checking namespace status: ", err)
				ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
					Status: server_structs.RespFailed,
					Msg:    "Error checking namespace status"})
				return
			}
			if existingStatus == Approved {
				log.Errorf("User '%s' is trying to modify approved namespace registration with id=%d", user, ns.ID)
				ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
					Status: server_structs.RespFailed,
					Msg:    "You don't have permission to modify an approved registration. Please contact your federation administrator"})
				return
			}
		}
		// If the user has previlege to udpate, go ahead
		if err := updateNamespace(&ns); err != nil {
			log.Errorf("Failed to update namespace with id %d. %v", ns.ID, err)
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Fail to update namespace"})
			return
		}
	}
}

// Get one namespace by id.
// Admin can see any namespace detail while non-admin can only see his/her namespace
//
// GET /namesapces/:id
func getNamespace(ctx *gin.Context) {
	user := ctx.GetString("User")
	idStr := ctx.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		// Handle the error if id is not a valid integer
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Invalid ID format. ID must a non-zero integer"})
		return
	}
	exists, err := namespaceExistsById(id)
	if err != nil {
		log.Error("Error checking if namespace exists: ", err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Error checking if namespace exists"})
		return
	}
	if !exists {
		log.Errorf("Namespace not found for id: %d", id)
		ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Namespace not found"})
		return
	}

	isAdmin, _ := web_ui.CheckAdmin(user)
	if !isAdmin { // Not admin, need to check if the namespace belongs to the user
		found, err := namespaceBelongsToUserId(id, user)
		if err != nil {
			log.Error("Error checking if namespace belongs to the user: ", err)
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Error checking if namespace belongs to the user"})
			return
		}
		if !found { // If the user doen's own the namespace, they can't update it
			log.Errorf("Namespace not found for id: %d", id)
			ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Namespace not found. Check the id or if you own the namespace"})
			return
		}
	}

	ns, err := getNamespaceById(id)
	if err != nil {
		log.Error("Error getting namespace: ", err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Error getting namespace"})
		return
	}
	ctx.JSON(http.StatusOK, ns)
}

func updateNamespaceStatus(ctx *gin.Context, status RegistrationStatus) {
	user := ctx.GetString("User")
	idStr := ctx.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		// Handle the error if id is not a valid integer
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Invalid ID format. ID must a non-zero integer"})
		return
	}
	exists, err := namespaceExistsById(id)
	if err != nil {
		log.Error("Error checking if namespace exists: ", err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Error checking if namespace exists"})
		return
	}
	if !exists {
		log.Errorf("Namespace not found for id: %d", id)
		ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Namespace not found"})
		return
	}

	if err = updateNamespaceStatusById(id, status, user); err != nil {
		log.Error("Error updating namespace status by ID:", id, " to status:", status)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to update namespace"})
		return
	}
	ctx.JSON(http.StatusOK,
		server_structs.SimpleApiResp{
			Status: server_structs.RespOK,
			Msg:    "success",
		})
}

func getNamespaceJWKS(ctx *gin.Context) {
	idStr := ctx.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		// Handle the error if id is not a valid integer
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Invalid ID format. ID must a non-zero integer"})
		return
	}
	found, err := namespaceExistsById(id)
	if err != nil {
		log.Errorf("Failed to check if namespace exists with id %d. %v", id, err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprint("Error checking id:", err)})
		return
	}
	if !found {
		ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Namespace not found"})
		return
	}
	jwks, err := getNamespaceJwksById(id)
	if err != nil {
		log.Errorf("Failed to get namespace jwks by id %d. %v", id, err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprint("Error getting jwks by id:", err)})
		return
	}
	jsonData, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		log.Errorf("Failed to marshall jwks. %v", err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to marshal JWKS"})
		return
	}
	// Append a new line to the JSON data
	jsonData = append(jsonData, '\n')
	ctx.Header("Content-Disposition", fmt.Sprintf("attachment; filename=public-key-server-%v.jwks", id))
	ctx.Data(200, "application/json", jsonData)
}

func deleteNamespace(ctx *gin.Context) {
	idStr := ctx.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		// Handle the error if id is not a valid integer
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Invalid ID format. ID must a non-zero integer"})
		return
	}
	exists, err := namespaceExistsById(id)
	if err != nil {
		log.Error("Error checking if namespace exists: ", err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Error checking if namespace exists"})
		return
	}
	if !exists {
		log.Errorf("Namespace not found for id: %d", id)
		ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Namespace not found"})
		return
	}
	err = deleteNamespaceByID(id)
	if err != nil {
		log.Errorf("Error deleting the namespace: %v", err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Error deleting the namespace"})
	}
	ctx.JSON(http.StatusOK,
		server_structs.SimpleApiResp{
			Status: server_structs.RespOK,
			Msg:    "success",
		})
}

func listInstitutions(ctx *gin.Context) {
	// When Registry.Institutions is set
	institutions := []Institution{}
	if err := param.Registry_Institutions.Unmarshal(&institutions); err != nil {
		log.Error("Fail to read server configuration of institutions", err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Fail to read server configuration of institutions"})
		return
	}

	if len(institutions) != 0 {
		ctx.JSON(http.StatusOK, institutions)
		return
	}

	// When Registry.InstitutionsUrl is set and Registry.Institutions is unset
	if institutionsCache != nil {
		insts, intErr, extErr := getCachedInstitutions()
		if intErr != nil || extErr != nil {
			if intErr != nil {
				log.Error(intErr)
			}
			if extErr != nil {
				ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
					Status: server_structs.RespFailed,
					Msg:    extErr.Error()})
			}
			return
		}
		ctx.JSON(http.StatusOK, insts)
		return
	}

	// When both are unset
	if len(institutions) == 0 {
		log.Error("Server didn't configure Registry.Institutions")
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Server didn't configure Registry.Institutions"})
		return
	}
}

func listTopologyNamespaces(ctx *gin.Context) {
	nss, err := getTopologyNamespaces()
	if err != nil {
		log.Errorf("failed to get all namespaces from the topology: %v", err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to get namespaces from topology"})
		return
	}
	ctx.JSON(http.StatusOK, nss)
}

// Define Gin APIs for registry Web UI. All endpoints are user-facing
func RegisterRegistryWebAPI(router *gin.RouterGroup) error {
	registryWebAPI := router.Group("/api/v1.0/registry_ui")
	csrfHandler, err := config.GetCSRFHandler()
	if err != nil {
		return err
	}
	// Add CSRF middleware to all the routes below. CSRF middleware will look for
	// any update methods (post/delete/patch, etc) and automatically check if a
	// X-CSRF-Token header is present and the token matches
	registryWebAPI.Use(csrfHandler)
	// Follow RESTful schema
	{
		registryWebAPI.GET("/namespaces", listNamespaces)
		registryWebAPI.OPTIONS("/namespaces", web_ui.AuthHandler, getNamespaceRegFields)
		registryWebAPI.POST("/namespaces", web_ui.AuthHandler, func(ctx *gin.Context) {
			createUpdateNamespace(ctx, false)
		})

		registryWebAPI.GET("/namespaces/user", web_ui.AuthHandler, listNamespacesForUser)

		registryWebAPI.GET("/namespaces/:id", web_ui.AuthHandler, getNamespace)
		registryWebAPI.PUT("/namespaces/:id", web_ui.AuthHandler, func(ctx *gin.Context) {
			createUpdateNamespace(ctx, true)
		})
		registryWebAPI.DELETE("/namespaces/:id", web_ui.AuthHandler, web_ui.AdminAuthHandler, deleteNamespace)
		registryWebAPI.GET("/namespaces/:id/pubkey", getNamespaceJWKS)
		registryWebAPI.PATCH("/namespaces/:id/approve", web_ui.AuthHandler, web_ui.AdminAuthHandler, func(ctx *gin.Context) {
			updateNamespaceStatus(ctx, Approved)
		})
		registryWebAPI.PATCH("/namespaces/:id/deny", web_ui.AuthHandler, web_ui.AdminAuthHandler, func(ctx *gin.Context) {
			updateNamespaceStatus(ctx, Denied)
		})
	}
	{
		registryWebAPI.GET("/topology", listTopologyNamespaces)
	}
	{
		registryWebAPI.GET("/institutions", web_ui.AuthHandler, listInstitutions)
	}
	return nil
}
