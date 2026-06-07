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

package transfer

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/param"
)

// handleCreateOAuthClient handles POST /api/v1.0/transfer/oauth-clients
func handleCreateOAuthClient(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !param.Transfer_EnableOAuth2Clients.GetBool() {
			c.JSON(http.StatusForbidden, ErrorResponse{
				Code:  "DISABLED",
				Error: "OAuth2 client management is disabled",
			})
			return
		}

		owner, err := getOwner(c)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to determine request owner",
			})
			return
		}

		var req OAuthClientCreateRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{
				Code:  "INVALID_REQUEST",
				Error: "Invalid request body: " + err.Error(),
			})
			return
		}

		encClientID, err := encryptSecret(req.ClientID)
		if err != nil {
			log.Errorf("Failed to encrypt client ID: %v", err)
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to encrypt client credentials",
			})
			return
		}

		encClientSecret, err := encryptSecret(req.ClientSecret)
		if err != nil {
			log.Errorf("Failed to encrypt client secret: %v", err)
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to encrypt client credentials",
			})
			return
		}

		client := TransferOAuthClient{
			ID:                    uuid.New().String(),
			UserID:                owner.UserID,
			Name:                  req.Name,
			IssuerURL:             req.IssuerURL,
			EncryptedClientID:     encClientID,
			EncryptedClientSecret: encClientSecret,
			GrantTypes:            req.GrantTypes,
			Scopes:                req.Scopes,
			CreatedAt:             time.Now(),
			UpdatedAt:             time.Now(),
		}

		if err := db.Create(&client).Error; err != nil {
			if isDuplicateKeyError(err) {
				c.JSON(http.StatusConflict, ErrorResponse{
					Code:  "CONFLICT",
					Error: "An OAuth2 client with this name already exists",
				})
				return
			}
			log.Errorf("Failed to create OAuth2 client: %v", err)
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to store OAuth2 client",
			})
			return
		}

		c.JSON(http.StatusCreated, oauthClientToResponse(&client))
	}
}

// handleListOAuthClients handles GET /api/v1.0/transfer/oauth-clients
func handleListOAuthClients(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !param.Transfer_EnableOAuth2Clients.GetBool() {
			c.JSON(http.StatusForbidden, ErrorResponse{
				Code:  "DISABLED",
				Error: "OAuth2 client management is disabled",
			})
			return
		}

		owner, err := getOwner(c)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to determine request owner",
			})
			return
		}

		var clients []TransferOAuthClient
		if err := db.Where("user_id = ?", owner.UserID).
			Order("created_at DESC").
			Find(&clients).Error; err != nil {
			log.Errorf("Failed to list OAuth2 clients: %v", err)
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to retrieve OAuth2 clients",
			})
			return
		}

		resp := make([]OAuthClientResponse, len(clients))
		for i, client := range clients {
			resp[i] = *oauthClientToResponse(&client)
		}

		c.JSON(http.StatusOK, resp)
	}
}

// handleDeleteOAuthClient handles DELETE /api/v1.0/transfer/oauth-clients/:id
func handleDeleteOAuthClient(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !param.Transfer_EnableOAuth2Clients.GetBool() {
			c.JSON(http.StatusForbidden, ErrorResponse{
				Code:  "DISABLED",
				Error: "OAuth2 client management is disabled",
			})
			return
		}

		owner, err := getOwner(c)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to determine request owner",
			})
			return
		}

		clientID := c.Param("id")
		result := db.Where("id = ? AND user_id = ?",
			clientID, owner.UserID).Delete(&TransferOAuthClient{})

		if result.Error != nil {
			log.Errorf("Failed to delete OAuth2 client: %v", result.Error)
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to delete OAuth2 client",
			})
			return
		}

		if result.RowsAffected == 0 {
			c.JSON(http.StatusNotFound, ErrorResponse{
				Code:  "NOT_FOUND",
				Error: "OAuth2 client not found",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "OAuth2 client deleted"})
	}
}

func oauthClientToResponse(client *TransferOAuthClient) *OAuthClientResponse {
	return &OAuthClientResponse{
		ID:         client.ID,
		Name:       client.Name,
		IssuerURL:  client.IssuerURL,
		GrantTypes: client.GrantTypes,
		Scopes:     client.Scopes,
		CreatedAt:  client.CreatedAt,
		UpdatedAt:  client.UpdatedAt,
	}
}
