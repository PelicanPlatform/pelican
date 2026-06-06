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
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// handleCreateCredential handles POST /api/v1.0/transfer/credentials
func handleCreateCredential(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		owner, err := getOwner(c)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to determine request owner",
			})
			return
		}

		var req CredentialCreateRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{
				Code:  "INVALID_REQUEST",
				Error: "Invalid request body: " + err.Error(),
			})
			return
		}

		encAccessToken, err := encryptSecret(req.AccessToken)
		if err != nil {
			log.Errorf("Failed to encrypt access token: %v", err)
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to encrypt credential",
			})
			return
		}

		cred := TransferCredential{
			ID:                   uuid.New().String(),
			UserID:               owner.UserID,
			Name:                 req.Name,
			CredentialType:       "bearer",
			EncryptedAccessToken: encAccessToken,
			TokenIssuer:          req.TokenIssuer,
			CreatedAt:            time.Now(),
			UpdatedAt:            time.Now(),
		}

		if err := db.Create(&cred).Error; err != nil {
			if errors.Is(err, gorm.ErrDuplicatedKey) || strings.Contains(err.Error(), "UNIQUE constraint failed") {
				c.JSON(http.StatusConflict, ErrorResponse{
					Code:  "CONFLICT",
					Error: "A credential with this name already exists",
				})
				return
			}
			log.Errorf("Failed to create credential: %v", err)
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to store credential",
			})
			return
		}

		c.JSON(http.StatusCreated, credentialToResponse(&cred))
	}
}

// handleListCredentials handles GET /api/v1.0/transfer/credentials
func handleListCredentials(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		owner, err := getOwner(c)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to determine request owner",
			})
			return
		}

		var creds []TransferCredential
		if err := db.Where("user_id = ?", owner.UserID).
			Order("created_at DESC").
			Find(&creds).Error; err != nil {
			log.Errorf("Failed to list credentials: %v", err)
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to retrieve credentials",
			})
			return
		}

		resp := make([]CredentialResponse, len(creds))
		for i, cred := range creds {
			resp[i] = *credentialToResponse(&cred)
		}

		c.JSON(http.StatusOK, resp)
	}
}

// handleGetCredential handles GET /api/v1.0/transfer/credentials/:id
func handleGetCredential(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		owner, err := getOwner(c)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to determine request owner",
			})
			return
		}

		credID := c.Param("id")
		cred, err := getOwnedCredential(db, credID, owner)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.JSON(http.StatusNotFound, ErrorResponse{
					Code:  "NOT_FOUND",
					Error: "Credential not found",
				})
			} else {
				c.JSON(http.StatusInternalServerError, ErrorResponse{
					Code:  "INTERNAL",
					Error: "Failed to retrieve credential",
				})
			}
			return
		}

		c.JSON(http.StatusOK, credentialToResponse(cred))
	}
}

// handleDeleteCredential handles DELETE /api/v1.0/transfer/credentials/:id
func handleDeleteCredential(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		owner, err := getOwner(c)
		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to determine request owner",
			})
			return
		}

		credID := c.Param("id")
		result := db.Where("id = ? AND user_id = ?",
			credID, owner.UserID).Delete(&TransferCredential{})

		if result.Error != nil {
			log.Errorf("Failed to delete credential: %v", result.Error)
			c.JSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to delete credential",
			})
			return
		}

		if result.RowsAffected == 0 {
			c.JSON(http.StatusNotFound, ErrorResponse{
				Code:  "NOT_FOUND",
				Error: "Credential not found",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Credential deleted"})
	}
}

// getOwnedCredential retrieves a credential by ID, verifying ownership
func getOwnedCredential(db *gorm.DB, credID string, owner ownerIdentity) (*TransferCredential, error) {
	var cred TransferCredential
	err := db.Where("id = ? AND user_id = ?",
		credID, owner.UserID).First(&cred).Error
	if err != nil {
		return nil, err
	}
	return &cred, nil
}

// getDecryptedAccessToken retrieves and decrypts the access token for a credential.
// The last_used_at column is updated at most once per lastUsedDebounce interval
// to avoid excessive writes when a credential is used in tight loops.
func getDecryptedAccessToken(db *gorm.DB, credID string, owner ownerIdentity) (string, error) {
	cred, err := getOwnedCredential(db, credID, owner)
	if err != nil {
		return "", err
	}

	if cred.EncryptedAccessToken == "" {
		return "", errors.New("credential has no access token")
	}

	decrypted, err := decryptSecret(cred.EncryptedAccessToken)
	if err != nil {
		return "", errors.Wrap(err, "failed to decrypt access token")
	}

	// Update last_used_at with debounce — skip if it was touched within
	// the debounce window.
	now := time.Now()
	if cred.LastUsedAt == nil || now.Sub(*cred.LastUsedAt) >= lastUsedDebounce {
		db.Model(&TransferCredential{}).Where("id = ?", credID).Update("last_used_at", now)
	}

	return decrypted, nil
}

// lastUsedDebounce is the minimum interval between successive last_used_at
// writes for a given credential.  This prevents excessive DB churn when a
// credential is resolved many times in a short burst (e.g. a multi-file
// recursive transfer).
const lastUsedDebounce = 5 * time.Minute

// credentialTokenProvider implements client.TokenProvider by dynamically
// fetching and decrypting a stored credential each time Get() is called.
// This allows tokens to be resolved at transfer-execution time instead of
// job-submission time, which matters when jobs may sit in a queue for hours.
type credentialTokenProvider struct {
	db           *gorm.DB
	credentialID string
	owner        ownerIdentity
}

// newCredentialTokenProvider creates a new credentialTokenProvider.
func newCredentialTokenProvider(db *gorm.DB, credentialID string, owner ownerIdentity) *credentialTokenProvider {
	return &credentialTokenProvider{
		db:           db,
		credentialID: credentialID,
		owner:        owner,
	}
}

// Get implements client.TokenProvider. It delegates to getDecryptedAccessToken
// which handles decryption and last_used_at debouncing.
func (p *credentialTokenProvider) Get() (string, error) {
	return getDecryptedAccessToken(p.db, p.credentialID, p.owner)
}

// credentialToResponse converts a credential model to the API response format
func credentialToResponse(cred *TransferCredential) *CredentialResponse {
	return &CredentialResponse{
		ID:             cred.ID,
		Name:           cred.Name,
		CredentialType: cred.CredentialType,
		TokenIssuer:    cred.TokenIssuer,
		TokenExpiry:    cred.TokenExpiry,
		LastUsedAt:     cred.LastUsedAt,
		CreatedAt:      cred.CreatedAt,
		UpdatedAt:      cred.UpdatedAt,
	}
}

// isDuplicateKeyError checks if a GORM error is a unique constraint violation
func isDuplicateKeyError(err error) bool {
	return err != nil && (errors.Is(err, gorm.ErrDuplicatedKey) || strings.Contains(err.Error(), "UNIQUE constraint failed"))
}
