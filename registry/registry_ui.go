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
		registrationFields = append(registrationFields, populateRegistrationFields("admin_metadata", AdminMetadata{})...)
	})
}

// Populate registrationFields array for frontend to send registration data
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
		// Find if the field has a json tag. Use the json tag name if so
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
			Required: field.Tag.Get("post") == "required",
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
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Server encountered an error trying to list namespaces"})
			return
		}
		nssWOPubkey := excludePubKey(namespaces)
		ctx.JSON(http.StatusOK, nssWOPubkey)

	} else {
		namespaces, err := getAllNamespaces()
		if err != nil {
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
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Error getting namespaces by user ID"})
	}
	ctx.JSON(http.StatusOK, namespaces)
}

func getNamespaceRegFields(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, registrationFields)
}

func createUpdateNamespace(ctx *gin.Context) {
	user := ctx.GetString("User")
	if user == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "You need to login to perform this action"})
		return
	}
	ns := Namespace{}
	if ctx.ShouldBindJSON(&ns) != nil {
		ctx.AbortWithStatusJSON(400, gin.H{"error": "Invalid create or update namespace request"})
	}
	if ns.ID == 0 { // Create
		ns.AdminMetadata.UserID = user
		if err := addNamespace(&ns); err != nil {
			log.Errorf("Failed to insert namespace with id %d. %v", ns.ID, err)
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Fail to insert namespace"})
		}
		ctx.JSON(http.StatusOK, gin.H{"message": "success"})
	} else { // Update
		exists, err := namespaceExistsById(ns.ID)
		if err != nil {
			log.Error("Failed to get namespace by ID:", err)
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Fail to find if namespace exists"})
		}
		if exists { // Update namespace if namespace exists
			if err := updateNamespace(&ns); err != nil {
				log.Errorf("Failed to update namespace with id %d. %v", ns.ID, err)
				ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Fail to update namespace"})
			}
		} else {
			ctx.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Can't update namespace: namespace not found"})
		}
	}
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

	if err = updateNamespaceStatusById(id, status, user); err != nil {
		log.Error("Error updating namespace status by ID:", id, " to status:", status)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to update namespace"})
	}
	ctx.JSON(http.StatusOK, gin.H{"message": "ok"})
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

// adminAuthHandler checks the admin status of a logged-in user. This middleware
// should be cascaded behind the [web_ui.AuthHandler]
func adminAuthHandler(ctx *gin.Context) {
	user := ctx.GetString("User")
	if user == "" {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Login required to view this page"})
	}
	if user == "admin" {
		ctx.Next()
		return
	}
	adminList := param.Registry_AdminUsers.GetStringSlice()
	for _, admin := range adminList {
		if user == admin {
			ctx.Next()
			return
		}
	}
	ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "You don't have permission to perform this action"})
}

func RegisterRegistryWebAPI(router *gin.RouterGroup) {
	registryWebAPI := router.Group("/api/v1.0/registry_ui")
	// Follow RESTful schema
	{
		registryWebAPI.GET("/namespaces", listNamespaces)
		registryWebAPI.POST("/namespaces", web_ui.AuthHandler, createUpdateNamespace)
		registryWebAPI.PUT("/namespaces", web_ui.AuthHandler, createUpdateNamespace)
		registryWebAPI.OPTIONS("/namespaces", web_ui.AuthHandler, getNamespaceRegFields)
		registryWebAPI.GET("/namespaces/user", web_ui.AuthHandler, listNamespacesForUser)
		registryWebAPI.GET("/namespaces/:id/pubkey", getNamespaceJWKS)
		registryWebAPI.PATCH("/namespaces/:id/approve", web_ui.AuthHandler, adminAuthHandler, func(ctx *gin.Context) {
			updateNamespaceStatus(ctx, Approved)
		})
		registryWebAPI.PATCH("/namespaces/:id/deny", web_ui.AuthHandler, adminAuthHandler, func(ctx *gin.Context) {
			updateNamespaceStatus(ctx, Denied)
		})
	}
}
