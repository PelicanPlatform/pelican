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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jellydator/ttlcache/v3"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/web_ui"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

type (
	listNamespaceRequest struct {
		ServerType string `form:"server_type"`
		Status     string `form:"status"`
	}

	listNamespacesForUserRequest struct {
		Status string `form:"status"`
	}

	registrationFieldType string
	registrationField     struct {
		Name     string                `json:"name"`
		Type     registrationFieldType `json:"type"`
		Required bool                  `json:"required"`
		Options  []interface{}         `json:"options"`
	}

	Institution struct {
		Name string `mapstructure:"name" json:"name" yaml:"name"`
		ID   string `mapstructure:"id" json:"id" yaml:"id"`
	}
)

const (
	String   registrationFieldType = "string"
	Int      registrationFieldType = "int"
	Enum     registrationFieldType = "enum"
	DateTime registrationFieldType = "datetime"
)

var (
	registrationFields     []registrationField
	institutionsCache      *ttlcache.Cache[string, []Institution]
	institutionsCacheMutex = sync.RWMutex{}
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

func checkUniqueInstitutions(insts []Institution) bool {
	repeatMap := make(map[string]bool)
	for _, inst := range insts {
		if repeatMap[inst.ID] {
			return false
		} else {
			repeatMap[inst.ID] = true
		}
	}
	return true
}

func getCachedInstitutions() (inst []Institution, intError error, extError error) {
	if institutionsCache == nil {
		return nil, errors.New("institutionsCache isn't initialized"), errors.New("Internal institution cache wasn't initialized")
	}
	instUrlStr := param.Registry_InstitutionsUrl.GetString()
	if instUrlStr == "" {
		intError = errors.New("Bad server configuration. Registry.InstitutionsUrl is unset")
		extError = errors.New("Bad server configuration. Registry.InstitutionsUrl is unset")
		return
	}
	instUrl, err := url.Parse(instUrlStr)
	if err != nil {
		intError = errors.Wrap(err, "Bad server configuration. Registry.InstitutionsUrl is invalid")
		extError = errors.New("Bad server configuration. Registry.InstitutionsUrl is invalid")
		return
	}
	if !institutionsCache.Has(instUrl.String()) {
		log.Info("Cache miss for institutions TTL cache. Will fetch from source.")
		client := &http.Client{Transport: config.GetTransport()}
		req, err := http.NewRequest("GET", instUrl.String(), nil)
		if err != nil {
			intError = errors.Wrap(err, "Error making a request when fetching institution list")
			extError = errors.New("Error when creating a request to fetch institution from remote url.")
			return
		}
		res, err := client.Do(req)
		if err != nil {
			intError = errors.Wrap(err, "Error response when fetching institution list")
			extError = errors.New("Error from response when fetching institution from remote url.")
			return
		}
		if res.StatusCode != 200 {
			intError = errors.Wrap(err, fmt.Sprintf("Error response when fetching institution list with code %d", res.StatusCode))
			extError = errors.New(fmt.Sprint("Error when fetching institution from remote url, remote server error with code: ", res.StatusCode))
			return
		}
		resBody, err := io.ReadAll(res.Body)
		if err != nil {
			intError = errors.Wrap(err, "Error reading response body when fetching institution list")
			extError = errors.New("Error read response when fetching institution from remote url.")
			return
		}
		institutions := []Institution{}
		if err = json.Unmarshal(resBody, &institutions); err != nil {
			intError = errors.Wrap(err, "Error parsing response body when fetching institution list")
			extError = errors.New("Error parsing response when fetching institution from remote url.")
			return
		}
		institutionsCacheMutex.Lock()
		defer institutionsCacheMutex.Unlock()
		institutionsCache.Set(instUrl.String(), institutions, ttlcache.DefaultTTL)
		return institutions, nil, nil
	} else {
		institutionsCacheMutex.RLock()
		defer institutionsCacheMutex.RUnlock()
		institutions := institutionsCache.Get(instUrl.String())
		if institutions.Value() == nil {
			intError = errors.New(fmt.Sprint("Fail to get institutions from internal TTL cache, value is nil from key: ", instUrl))
			extError = errors.New("Fail to get institutions from internal TTL cache")
			return
		}
		if institutions.IsExpired() {
			intError = errors.New(fmt.Sprintf("Cached institution with key %q is expired at %v", institutions.Key(), institutions.ExpiresAt()))
			extError = errors.New("Expired institution cache")
			return
		}
		return institutions.Value(), nil, nil
	}
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
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check user login status"})
		return
	}
	ctx.Set("User", user)
	isAuthed := user != ""
	queryParams := listNamespaceRequest{}
	if ctx.ShouldBindQuery(&queryParams) != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid query parameters"})
		return
	}

	// For unauthed user with non-empty Status query != Approved, return 403
	if !isAuthed && queryParams.Status != "" && queryParams.Status != Approved.String() {
		ctx.JSON(http.StatusForbidden, gin.H{"error": "You don't have permission to filter non-approved namespace registrations"})
		return
	}

	// Filter ns by server type
	if queryParams.ServerType != "" && queryParams.ServerType != string(OriginType) && queryParams.ServerType != string(CacheType) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server type"})
		return
	}

	filterNs := Namespace{}

	// For authenticated users, it returns all namespaces.
	// For unauthenticated users, it returns namespaces with AdminMetadata.Status = Approved
	if isAuthed {
		if queryParams.Status != "" {
			filterNs.AdminMetadata.Status = RegistrationStatus(queryParams.Status)
		}
	} else {
		filterNs.AdminMetadata.Status = Approved
	}

	namespaces, err := getNamespacesByFilter(filterNs, ServerType(queryParams.ServerType))
	if err != nil {
		log.Error("Failed to get namespaces by server type: ", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Server encountered an error trying to list namespaces"})
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
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "You need to login to perform this action"})
		return
	}
	queryParams := listNamespacesForUserRequest{}
	if ctx.ShouldBindQuery(&queryParams) != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid query parameters"})
		return
	}

	filterNs := Namespace{AdminMetadata: AdminMetadata{UserID: user}}

	if queryParams.Status != "" {
		filterNs.AdminMetadata.Status = RegistrationStatus(queryParams.Status)
	}

	namespaces, err := getNamespacesByFilter(filterNs, "")
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
	// Assign ID from path param because the request data doesn't have ID set
	ns.ID = id
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

	if !isUpdate {
		// Check if prefix exists before doing anything else. Skip check if it's update operation
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
		log.Errorln(valErr)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": valErr})
		return
	}
	if sysErr != nil {
		log.Errorln(sysErr)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": sysErr})
		return
	}

	if validInst, err := validateInstitution(ns.AdminMetadata.Institution); !validInst {
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Error validating institution: %v", err)})
			return
		}
		ctx.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Institution \"%s\" is not in the list of available institutions to register.", ns.AdminMetadata.Institution)})
		return
	}

	if !isUpdate { // Create
		ns.AdminMetadata.UserID = user
		// Overwrite status to Pending to filter malicious request
		ns.AdminMetadata.Status = Pending
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
		isAdmin, _ := web_ui.CheckAdmin(user)
		if !isAdmin { // Not admin, need to check if the namespace belongs to the user
			found, err := namespaceBelongsToUserId(ns.ID, user)
			if err != nil {
				log.Error("Error checking if namespace belongs to the user: ", err)
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Error checking if namespace belongs to the user"})
				return
			}
			if !found {
				log.Errorf("Namespace not found for id: %d", ns.ID)
				ctx.JSON(http.StatusNotFound, gin.H{"error": "Namespace not found. Check the id or if you own the namespace"})
				return
			}
			existingStatus, err := getNamespaceStatusById(ns.ID)
			if err != nil {
				log.Error("Error checking namespace status: ", err)
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Error checking namespace status"})
				return
			}
			if existingStatus == Approved {
				log.Errorf("User '%s' is trying to modify approved namespace registration with id=%d", user, ns.ID)
				ctx.JSON(http.StatusForbidden, gin.H{"error": "You don't have permission to modify an approved registration. Please contact your federation administrator"})
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

	isAdmin, _ := web_ui.CheckAdmin(user)
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

func listInstitutions(ctx *gin.Context) {
	// When Registry.InstitutionsUrl is set and Registry.Institutions is unset
	if institutionsCache != nil {
		insts, intErr, extErr := getCachedInstitutions()
		if intErr != nil || extErr != nil {
			if intErr != nil {
				log.Error(intErr)
			}
			if extErr != nil {
				ctx.JSON(http.StatusInternalServerError, gin.H{"error": extErr.Error()})
			}
			return
		}
		ctx.JSON(http.StatusOK, insts)
		return
	}
	// When Registry.Institutions is set
	institutions := []Institution{}
	if err := param.Registry_Institutions.Unmarshal(&institutions); err != nil {
		log.Error("Fail to read server configuration of institutions", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Fail to read server configuration of institutions"})
		return
	}

	if len(institutions) == 0 {
		log.Error("Server didn't configure Registry.Institutions")
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Server didn't configure Registry.Institutions"})
		return
	}
	ctx.JSON(http.StatusOK, institutions)
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
		registryWebAPI.PATCH("/namespaces/:id/approve", web_ui.AuthHandler, web_ui.AdminAuthHandler, func(ctx *gin.Context) {
			updateNamespaceStatus(ctx, Approved)
		})
		registryWebAPI.PATCH("/namespaces/:id/deny", web_ui.AuthHandler, web_ui.AdminAuthHandler, func(ctx *gin.Context) {
			updateNamespaceStatus(ctx, Denied)
		})
	}
	{
		registryWebAPI.GET("/institutions", web_ui.AuthHandler, listInstitutions)
	}
	return nil
}

// Initialize institutions list
func InitInstConfig(ctx context.Context, egrp *errgroup.Group) error {
	institutions := []Institution{}
	if err := param.Registry_Institutions.Unmarshal(&institutions); err != nil {
		log.Error("Fail to read Registry.Institutions. Make sure you had the correct format", err)
		return errors.Wrap(err, "Fail to read Registry.Institutions. Make sure you had the correct format")
	}

	if param.Registry_InstitutionsUrl.GetString() != "" {
		// Read from Registry.Institutions if Registry.InstitutionsUrl is empty
		// or Registry.Institutions and Registry.InstitutionsUrl are both set
		if len(institutions) > 0 {
			log.Warning("Registry.Institutions and Registry.InstitutionsUrl are both set. Registry.InstitutionsUrl is ignored")
			if !checkUniqueInstitutions(institutions) {
				return errors.Errorf("Institution IDs read from config are not unique")
			}
			// return here so that we don't init the institution url cache
			return nil
		}

		_, err := url.Parse(param.Registry_InstitutionsUrl.GetString())
		if err != nil {
			log.Error("Invalid Registry.InstitutionsUrl: ", err)
			return errors.Wrap(err, "Invalid Registry.InstitutionsUrl")
		}
		instCacheTTL := param.Registry_InstitutionsUrlReloadMinutes.GetDuration()

		institutionsCache = ttlcache.New[string, []Institution](ttlcache.WithTTL[string, []Institution](instCacheTTL))

		go institutionsCache.Start()

		egrp.Go(func() error {
			<-ctx.Done()
			institutionsCacheMutex.Lock()
			defer institutionsCacheMutex.Unlock()
			log.Info("Gracefully stopping institution TTL cache eviction...")
			if institutionsCache != nil {
				institutionsCache.DeleteAll()
				institutionsCache.Stop()
			} else {
				log.Info("Institution TTL cache is nil, stop clean up process.")
			}
			return nil
		})

		// Try to populate the cache at the server start. If error occured, it's non-blocking
		cachedInsts, intErr, _ := getCachedInstitutions()
		if intErr != nil {
			log.Warning("Failed to populate institution cache. It's non-blocking. Error: ", intErr)
		} else {
			if !checkUniqueInstitutions(cachedInsts) {
				return errors.Errorf("Institution IDs read from config are not unique")
			}
			log.Infof("Successfully populated institution TTL cache with %d entries", len(institutionsCache.Get(institutionsCache.Keys()[0]).Value()))
		}
	}

	if !checkUniqueInstitutions(institutions) {
		return errors.Errorf("Institution IDs read from config are not unique")
	}
	// Else we will read from Registry.Institutions. No extra action needed.
	return nil
}
