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

package nsregistry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

type listNamespaceRequest struct {
	ServerType string `form:"server_type"`
}

// Exclude pubkey field from marshalling into json
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
	jwks, err := getPrefixJwksById(id)
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

func RegisterNamespacesRegistryWebAPI(router *gin.RouterGroup) {
	registryWebAPI := router.Group("/api/v1.0/registry_ui")
	// Follow RESTful schema
	{
		registryWebAPI.GET("/namespaces", listNamespaces)
		registryWebAPI.GET("/namespaces/:id/pubkey", getNamespaceJWKS)
	}
}
