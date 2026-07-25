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
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	oauth2_upstream "golang.org/x/oauth2"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/config"
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

		encAccessToken, err := encryptSecret(req.AccessToken, owner.UserID, fieldCredAccessToken)
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

// getDecryptedAccessToken retrieves and decrypts the access token for a
// credential, first refreshing it when it is near expiry and a refresh token is
// available. Because jobs may sit in a queue for hours, the delegated access
// token can expire before the transfer runs; the server refreshes it here rather
// than sending a stale token that the destination would reject. If the token is
// already expired and cannot be refreshed, this fails fast with a clear error
// instead of returning a token that is guaranteed to be rejected.
//
// The last_used_at column is updated at most once per lastUsedDebounce interval
// to avoid excessive writes when a credential is used in tight loops.
func getDecryptedAccessToken(db *gorm.DB, credID string, owner ownerIdentity) (string, error) {
	cred, err := getOwnedCredential(db, credID, owner)
	if err != nil {
		return "", err
	}

	if credentialNeedsRefresh(cred) {
		if refreshErr := refreshCredentialToken(db, cred, owner); refreshErr != nil {
			// Reload in case a concurrent resolve refreshed it while we waited.
			if reloaded, loadErr := getOwnedCredential(db, credID, owner); loadErr == nil {
				cred = reloaded
			}
			if credentialExpired(cred) {
				return "", errors.Wrap(refreshErr, "credential token expired and could not be refreshed")
			}
			log.Warnf("Transfer credential %s: refresh failed but a usable token remains: %v", credID, refreshErr)
		} else if reloaded, loadErr := getOwnedCredential(db, credID, owner); loadErr == nil {
			cred = reloaded
		}
	} else if credentialExpired(cred) {
		// Expired with no way to refresh (no refresh token / issuer). Fail fast
		// rather than hand back a token the destination will reject.
		return "", errors.New("credential token has expired and has no refresh token")
	}

	if cred.EncryptedAccessToken == "" {
		return "", errors.New("credential has no access token")
	}

	decrypted, err := decryptSecret(cred.EncryptedAccessToken, cred.UserID, fieldCredAccessToken)
	if err != nil {
		return "", errors.Wrap(err, "failed to decrypt access token")
	}

	// Update last_used_at with debounce, enforced in the WHERE clause so
	// concurrent resolves of the same credential don't race on a read-then-write
	// (each would otherwise re-read the same stale timestamp and both write).
	now := time.Now()
	db.Model(&TransferCredential{}).
		Where("id = ? AND (last_used_at IS NULL OR last_used_at < ?)", credID, now.Add(-lastUsedDebounce)).
		Update("last_used_at", now)

	return decrypted, nil
}

// lastUsedDebounce is the minimum interval between successive last_used_at
// writes for a given credential.  This prevents excessive DB churn when a
// credential is resolved many times in a short burst (e.g. a multi-file
// recursive transfer).
const lastUsedDebounce = 5 * time.Minute

// tokenRefreshMargin is how far ahead of a credential's expiry the server
// proactively refreshes its access token.
const tokenRefreshMargin = 5 * time.Minute

// credentialRefreshLocks serializes refreshes per credential so concurrent
// transfers sharing a credential do not each hit the issuer or race on the
// persisted result.
var credentialRefreshLocks sync.Map // credentialID -> *sync.Mutex

func credentialRefreshLock(id string) *sync.Mutex {
	m, _ := credentialRefreshLocks.LoadOrStore(id, &sync.Mutex{})
	return m.(*sync.Mutex)
}

// credentialExpired reports whether the credential's access token is at or past
// its known expiry. An unknown expiry (nil) is treated as not-expired.
func credentialExpired(cred *TransferCredential) bool {
	return cred.TokenExpiry != nil && !time.Now().Before(*cred.TokenExpiry)
}

// credentialRefreshable reports whether the credential carries what is needed to
// perform a refresh-token grant.
func credentialRefreshable(cred *TransferCredential) bool {
	return cred.TokenIssuer != "" &&
		cred.EncryptedRefreshToken != nil && *cred.EncryptedRefreshToken != ""
}

// credentialNeedsRefresh reports whether the credential is refreshable and its
// access token is missing or within the refresh margin of expiry.
func credentialNeedsRefresh(cred *TransferCredential) bool {
	if !credentialRefreshable(cred) {
		return false
	}
	if cred.EncryptedAccessToken == "" {
		return true
	}
	return cred.TokenExpiry != nil && time.Until(*cred.TokenExpiry) < tokenRefreshMargin
}

// refreshCredentialToken performs a refresh-token grant for the credential and
// persists the rotated access (and refresh) token. It serializes per credential
// and re-checks the need under the lock so a concurrent refresh is not repeated.
func refreshCredentialToken(db *gorm.DB, cred *TransferCredential, owner ownerIdentity) error {
	lock := credentialRefreshLock(cred.ID)
	lock.Lock()
	defer lock.Unlock()

	// Re-read under the lock; another goroutine may have just refreshed.
	current, err := getOwnedCredential(db, cred.ID, owner)
	if err != nil {
		return err
	}
	if !credentialNeedsRefresh(current) {
		*cred = *current
		return nil
	}

	refreshToken, err := decryptSecret(*current.EncryptedRefreshToken, current.UserID, fieldCredRefreshToken)
	if err != nil {
		return errors.Wrap(err, "failed to decrypt refresh token")
	}

	// The OAuth client used for the refresh grant is not recorded on the
	// credential, so resolve it by (owner, issuer), preferring the user's own
	// client over an admin-configured shared one.
	var oauthClient TransferOAuthClient
	if err := db.Where("user_id = ? AND issuer_url = ?", owner.UserID, current.TokenIssuer).
		Order("admin_configured ASC").First(&oauthClient).Error; err != nil {
		return errors.Wrap(err, "no OAuth client registered for this credential's issuer to refresh with")
	}
	clientID, err := decryptSecret(oauthClient.EncryptedClientID, oauthClient.UserID, fieldClientID)
	if err != nil {
		return errors.Wrap(err, "failed to decrypt OAuth client id")
	}
	clientSecret, err := decryptSecret(oauthClient.EncryptedClientSecret, oauthClient.UserID, fieldClientSecret)
	if err != nil {
		return errors.Wrap(err, "failed to decrypt OAuth client secret")
	}

	issuerMeta, err := config.GetIssuerMetadata(current.TokenIssuer)
	if err != nil {
		return errors.Wrap(err, "failed to get issuer metadata")
	}

	upstreamConfig := oauth2_upstream.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2_upstream.Endpoint{
			AuthURL:  issuerMeta.AuthURL,
			TokenURL: issuerMeta.TokenURL,
		},
	}
	// Expiry in the past forces the token source to use the refresh token.
	seed := &oauth2_upstream.Token{RefreshToken: refreshToken, Expiry: time.Unix(0, 0)}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	httpClient := &http.Client{Transport: config.GetSSRFHttpTransport()}
	ctx = context.WithValue(ctx, oauth2_upstream.HTTPClient, httpClient)

	newToken, err := upstreamConfig.TokenSource(ctx, seed).Token()
	if err != nil {
		return errors.Wrap(err, "refresh-token grant failed")
	}

	encAccess, err := encryptSecret(newToken.AccessToken, current.UserID, fieldCredAccessToken)
	if err != nil {
		return errors.Wrap(err, "failed to encrypt refreshed access token")
	}
	updates := map[string]any{
		"encrypted_access_token": encAccess,
		"updated_at":             time.Now(),
	}
	// Some issuers omit expires_in on refresh; leave expiry unknown (nil) in that
	// case rather than storing the zero time, which would read as long-expired.
	if !newToken.Expiry.IsZero() {
		expiry := newToken.Expiry
		updates["token_expiry"] = expiry
		current.TokenExpiry = &expiry
	} else {
		updates["token_expiry"] = nil
		current.TokenExpiry = nil
	}
	// Persist a rotated refresh token if the issuer returned one.
	if newToken.RefreshToken != "" && newToken.RefreshToken != refreshToken {
		encRefresh, encErr := encryptSecret(newToken.RefreshToken, current.UserID, fieldCredRefreshToken)
		if encErr != nil {
			return errors.Wrap(encErr, "failed to encrypt rotated refresh token")
		}
		updates["encrypted_refresh_token"] = encRefresh
		current.EncryptedRefreshToken = &encRefresh
	}

	if err := db.Model(&TransferCredential{}).Where("id = ?", current.ID).Updates(updates).Error; err != nil {
		return errors.Wrap(err, "failed to persist refreshed credential")
	}

	current.EncryptedAccessToken = encAccess
	*cred = *current
	log.Debugf("Refreshed transfer credential %s access token", cred.ID)
	return nil
}

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
