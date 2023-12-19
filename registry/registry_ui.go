/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/web_ui"
	log "github.com/sirupsen/logrus"
)

type (
	listNamespaceRequest struct {
		ServerType string `form:"server_type"`
	}

	registrationFieldType string
	registrationField     struct {
		Name     string                `json:"name"`
		Type     registrationFieldType `json:"type"`
		Required bool                  `json:"required"`
		Options  []interface{}         `json:"options"`
	}
)

const (
	String   registrationFieldType = "string"
	Int      registrationFieldType = "int"
	Enum     registrationFieldType = "enum"
	DateTime registrationFieldType = "datetime"
)

var (
	registrationFields        []registrationField
	setRegistrationFieldsOnce sync.Once
)

func init() {
	setRegistrationFieldsOnce.Do(func() {
		registrationFields = make([]registrationField, 0)
		registrationFields = append(registrationFields, populateRegistrationFields("", Namespace{})...)
	})
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
				// `json:"-"` means this field should be removed from any marshalling
				continue
			}
		}

		regField := registrationField{
			Name:     name + tempName,
			Required: strings.Contains(field.Tag.Get("validate"), "required"),
		}

		switch field.Type.Kind() {
		case reflect.Int:
			regField.Type = Int
			fields = append(fields, regField)
			break
		case reflect.String:
			regField.Type = String
			fields = append(fields, regField)
			break
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
				break
			}
		}

		if field.Type == reflect.TypeOf(RegistrationStatus(0)) {
			regField.Type = Enum
			options := make([]interface{}, 3)
			options[0] = Pending
			options[1] = Approved
			options[2] = Denied
			regField.Options = options
			fields = append(fields, regField)
		} else {
			// Skip the field if it's not in the types listed above
			continue
		}
	}
	return fields
}

// Helper function to exclude pubkey field from marshalling into json
func excludePubKey(nss []*Namespace) (nssNew []NamespaceWOPubkey) {
	nssNew = make([]NamespaceWOPubkey, 0)
	for _, ns := range nss {
		nsNew := NamespaceWOPubkey{
			ID:            ns.ID,
			Prefix:        ns.Prefix,
			Pubkey:        ns.Pubkey,
			AdminMetadata: ns.AdminMetadata,
			Identity:      ns.Identity,
		}
		nssNew = append(nssNew, nsNew)
	}

	return
}

func listNamespaces(ctx *gin.Context) {
	queryParams := listNamespaceRequest{}
	if ctx.ShouldBindQuery(&queryParams) != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid query parameters"})
		return
	}

	if queryParams.ServerType != "" {
		if queryParams.ServerType != string(OriginType) && queryParams.ServerType != string(CacheType) {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server type"})
			return
		}
		namespaces, err := getNamespacesByServerType(ServerType(queryParams.ServerType))
		if err != nil {
			log.Error("Failed to get namespaces by server type: ", err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Server encountered an error trying to list namespaces"})
			return
		}
		nssWOPubkey := excludePubKey(namespaces)
		ctx.JSON(http.StatusOK, nssWOPubkey)

	} else {
		namespaces, err := getAllNamespaces()
		if err != nil {
			log.Error("Failed to get all namespaces: ", err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Server encountered an error trying to list namespaces"})
			return
		}
		nssWOPubkey := excludePubKey(namespaces)
		ctx.JSON(http.StatusOK, nssWOPubkey)
	}
}

func listNamespacesForUser(ctx *gin.Context) {
	user := ctx.GetString("User")
	if user == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "You need to login to perform this action"})
		return
	}
	namespaces, err := getNamespacesByUserID(user)
	if err != nil {
		log.Error("Error getting namespaces for user ", user)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Error getting namespaces by user ID"})
		return
	}
	ctx.JSON(http.StatusOK, namespaces)
}

func getNamespaceRegFields(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, registrationFields)
}

func createUpdateNamespace(ctx *gin.Context, isUpdate bool) {
	user := ctx.GetString("User")
	id := 0 // namespace ID when doing update
	if user == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "You need to login to perform this action"})
		return
	}
	if isUpdate {
		idStr := ctx.Param("id")
		var err error
		id, err = strconv.Atoi(idStr)
		if err != nil || id <= 0 {
			// Handle the error if id is not a valid integer
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID format. ID must a non-zero integer"})
			return
		}
	}

	ns := Namespace{}
	if ctx.ShouldBindJSON(&ns) != nil {
		ctx.JSON(400, gin.H{"error": "Invalid create or update namespace request"})
		return
	}
	// Basic validation (type, required, etc)
	errs := config.GetValidate().Struct(ns)
	if errs != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprint(errs)})
		return
	}
	// Check that Prefix is a valid prefix
	updated_prefix, err := validatePrefix(ns.Prefix)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprint("Error: Field validation for prefix failed:", err)})
		return
	}
	ns.Prefix = updated_prefix

	// Check if prefix exists before doing anything else
	exists, err := namespaceExists(ns.Prefix)
	if err != nil {
		log.Errorf("Failed to check if namespace already exists: %v", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Server encountered an error checking if namespace already exists"})
		return
	}
	if exists {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("The prefix %s is already registered", ns.Prefix)})
		return
	}
	// Check if pubKey is a valid JWK
	pubkey, err := validateJwks(ns.Pubkey)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprint("Error: Field validation for pubkey failed:", err)})
		return
	}

	// Check if the parent or child path along the prefix has been registered
	valErr, sysErr := validateKeyChaining(ns.Prefix, pubkey)
	if valErr != nil {
		log.Errorln(err)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err})
		return
	}
	if sysErr != nil {
		log.Errorln(err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	if !isUpdate { // Create
		ns.AdminMetadata.UserID = user
		if err := addNamespace(&ns); err != nil {
			log.Errorf("Failed to insert namespace with id %d. %v", ns.ID, err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Fail to insert namespace"})
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"msg": "success"})
	} else { // Update
		// First check if the namespace exists
		exists, err := namespaceExistsById(ns.ID)
		if err != nil {
			log.Error("Failed to get namespace by ID:", err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Fail to find if namespace exists"})
			return
		}

		if !exists { // Return 404 is the namespace does not exists
			ctx.JSON(http.StatusNotFound, gin.H{"error": "Can't update namespace: namespace not found"})
			return
		}

		// Then check if the user has previlege to update
		isAdmin, _ := checkAdmin(user)
		if !isAdmin { // Not admin, need to check if the namespace belongs to the user
			found, err := namespaceBelongsToUserId(id, user)
			if err != nil {
				log.Error("Error checking if namespace belongs to the user: ", err)
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Error checking if namespace belongs to the user"})
				return
			}
			if !found {
				log.Errorf("Namespace not found for id: %d", id)
				ctx.JSON(http.StatusNotFound, gin.H{"error": "Namespace not found. Check the id or if you own the namespace"})
				return
			}
		}
		// If the user has previlege to udpate, go ahead
		if err := updateNamespace(&ns); err != nil {
			log.Errorf("Failed to update namespace with id %d. %v", ns.ID, err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Fail to update namespace"})
			return
		}
	}
}

func getNamespace(ctx *gin.Context) {
	// Admin can see any namespace detail while non-admin can only see his/her namespace
	user := ctx.GetString("User")
	idStr := ctx.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		// Handle the error if id is not a valid integer
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID format. ID must a non-zero integer"})
		return
	}
	exists, err := namespaceExistsById(id)
	if err != nil {
		log.Error("Error checking if namespace exists: ", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Error checking if namespace exists"})
		return
	}
	if !exists {
		log.Errorf("Namespace not found for id: %d", id)
		ctx.JSON(http.StatusNotFound, gin.H{"error": "Namespace not found"})
		return
	}

	isAdmin, _ := checkAdmin(user)
	if !isAdmin { // Not admin, need to check if the namespace belongs to the user
		found, err := namespaceBelongsToUserId(id, user)
		if err != nil {
			log.Error("Error checking if namespace belongs to the user: ", err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Error checking if namespace belongs to the user"})
			return
		}
		if !found { // If the user doen's own the namespace, they can't update it
			log.Errorf("Namespace not found for id: %d", id)
			ctx.JSON(http.StatusForbidden, gin.H{"error": "Namespace not found. Check the id or if you own the namespace"})
			return
		}
	}

	ns, err := getNamespaceById(id)
	if err != nil {
		log.Error("Error getting namespace: ", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Error getting namespace"})
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
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID format. ID must a non-zero integer"})
		return
	}
	exists, err := namespaceExistsById(id)
	if err != nil {
		log.Error("Error checking if namespace exists: ", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Error checking if namespace exists"})
		return
	}
	if !exists {
		log.Errorf("Namespace not found for id: %d", id)
		ctx.JSON(http.StatusNotFound, gin.H{"error": "Namespace not found"})
		return
	}

	if err = updateNamespaceStatusById(id, status, user); err != nil {
		log.Error("Error updating namespace status by ID:", id, " to status:", status)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update namespace"})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"msg": "ok"})
}

func getNamespaceJWKS(ctx *gin.Context) {
	idStr := ctx.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		// Handle the error if id is not a valid integer
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID format. ID must a non-zero integer"})
		return
	}
	found, err := namespaceExistsById(id)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprint("Error checking id:", err)})
		return
	}
	if !found {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "Namespace not found"})
		return
	}
	jwks, err := getNamespaceJwksById(id)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprint("Error getting jwks by id:", err)})
		return
	}
	jsonData, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to marshal JWKS"})
		return
	}
	// Append a new line to the JSON data
	jsonData = append(jsonData, '\n')
	ctx.Header("Content-Disposition", fmt.Sprintf("attachment; filename=public-key-server-%v.jwks", id))
	ctx.Data(200, "application/json", jsonData)
}

// checkAdmin checks if a user string has admin privilege. It returns boolean and a message
// indicating the error message
func checkAdmin(user string) (isAdmin bool, message string) {
	if user == "admin" {
		return true, ""
	}
	adminList := param.Registry_AdminUsers.GetStringSlice()
	for _, admin := range adminList {
		if user == admin {
			return true, ""
		}
	}
	return false, "You don't have permission to perform this action"
}

// adminAuthHandler checks the admin status of a logged-in user. This middleware
// should be cascaded behind the [web_ui.AuthHandler]
func adminAuthHandler(ctx *gin.Context) {
	user := ctx.GetString("User")
	// This should be done by a regular auth handler from the upstream, but we check here just in case
	if user == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Login required to view this page"})
	}
	isAdmin, msg := checkAdmin(user)
	if isAdmin {
		ctx.Next()
		return
	} else {
		ctx.JSON(http.StatusForbidden, gin.H{"error": msg})
	}
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
		registryWebAPI.GET("/namespaces/:id/pubkey", getNamespaceJWKS)
		registryWebAPI.PATCH("/namespaces/:id/approve", web_ui.AuthHandler, adminAuthHandler, func(ctx *gin.Context) {
			updateNamespaceStatus(ctx, Approved)
		})
		registryWebAPI.PATCH("/namespaces/:id/deny", web_ui.AuthHandler, adminAuthHandler, func(ctx *gin.Context) {
			updateNamespaceStatus(ctx, Denied)
		})
	}
	return nil
}
