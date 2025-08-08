package database

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/server_structs"
)

func generateSecret(length int) ([]byte, error) {
	bytesSlice := make([]byte, length)
	_, err := rand.Read(bytesSlice)
	if err != nil {
		return nil, err
	}
	return bytesSlice, nil
}

func generateTokenID(secret []byte) string {
	hash := sha256.Sum256(secret)
	return hex.EncodeToString(hash[:])[:5]
}

// VerifyApiKey verifies the API key and returns the capabilities associated with the key.
// It assumes that the API key is in the format "$ID.$SECRET_IN_HEX".
// It returns true if the API key is valid, false if the API key is invalid, and an error if an error occurred.
// If the API key is valid, it also returns the capabilities associated with the key.
func VerifyApiKey(db *gorm.DB, apiKey string, verifiedKeysCache *ttlcache.Cache[string, server_structs.ApiKeyCached]) (bool, []string, error) {
	parts := strings.Split(apiKey, ".")
	if len(parts) != 2 {
		return false, nil, errors.New("invalid API key format")
	}
	id := parts[0]
	secretHex := parts[1]

	item := verifiedKeysCache.Get(id)
	if item != nil {
		// Cache hit
		cached := item.Value()
		if cached.Token == apiKey { // check the cached token matches the one we are trying to verify
			// check if the token has expired
			if !cached.ExpiresAt.IsZero() && time.Now().UTC().After(cached.ExpiresAt) {
				return false, nil, errors.New("Token has expired")
			}
			return true, cached.Capabilities, nil
		} // otherwise the api token doesn't match the one in the cache so we do a hard check
	}

	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		return false, nil, errors.New("Failed to decode the secret")
	}

	var token server_structs.ApiKey
	result := db.First(&token, "id = ?", id)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return false, nil, errors.New("Token not found") // token not found
		}
		return false, nil, errors.New("Failed to retrieve the API key")
	}

	// Check if the token has expired
	// If the token has an expiration time and the current time is after the expiration time, the token is invalid
	if !token.ExpiresAt.IsZero() && time.Now().UTC().After(token.ExpiresAt) {
		return false, nil, errors.New("Token has expired")
	}

	// We compare the hashed value of the secret with the stored hashed value
	// If there is a match, the API key is valid
	// Otherwise, the API key is invalid
	err = bcrypt.CompareHashAndPassword([]byte(token.HashedValue), []byte(secret))
	if err != nil {
		return false, nil, errors.New("Invalid API token")
	}

	// Cache the verified API key
	// Keys that have an expiration time are cached with a TTL equal to the time until expiration
	// Keys that don't have an expiration time are cached with the default TTL
	cacheTTL := ttlcache.DefaultTTL
	if !token.ExpiresAt.IsZero() {
		timeUntilExpiration := time.Until(token.ExpiresAt)
		if timeUntilExpiration < cacheTTL {
			cacheTTL = timeUntilExpiration
		}
	}

	cached := server_structs.ApiKeyCached{
		Token:        apiKey,
		Capabilities: strings.Split(token.Scopes, ","),
		ExpiresAt:    token.ExpiresAt,
	}
	verifiedKeysCache.Set(id, cached, cacheTTL)
	return true, cached.Capabilities, nil
}

// CreateApiKey creates a new API key with the given name, creator, scopes, and expiration time.
// It returns the API key in the format "$ID.$SECRET_IN_HEX" and an error if an error occurred.
// The scopes can are a comma-separated list of capabilities. i.e "monitoring.query,monitoring.scrape"
// The scopes are defined in the token_scopes package
func CreateApiKey(db *gorm.DB, name, createdBy, scopes string, expiration time.Time) (string, error) {
	for {
		secret, err := generateSecret(32)
		if err != nil {
			return "", errors.Wrap(err, "failed to generate a secret")
		}

		id := generateTokenID(secret)

		hashedValue, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
		if err != nil {
			return "", errors.Wrap(err, "failed to hash the secret")
		}

		apiKey := server_structs.ApiKey{
			ID:          id,
			Name:        name,
			HashedValue: string(hashedValue),
			Scopes:      scopes,
			ExpiresAt:   expiration.UTC(),
			CreatedAt:   time.Now().UTC(),
			CreatedBy:   createdBy,
		}
		result := db.Create(apiKey)
		if result.Error != nil {
			isConstraintError := errors.Is(result.Error, gorm.ErrDuplicatedKey)
			if !isConstraintError {
				return "", errors.Wrap(result.Error, "failed to create a new API key")
			}
			// If the ID is already taken, try again
			continue
		}
		return fmt.Sprintf("%s.%s", id, hex.EncodeToString(secret)), nil
	}
}

// DeleteApiKey deletes the API key with the given ID.
// It returns an error if an error occurred.
// It also removes the API key from the verifiedKeysCache so that the deleted key is no longer valid.
func DeleteApiKey(db *gorm.DB, id string, verifiedKeysCache *ttlcache.Cache[string, server_structs.ApiKeyCached]) error {
	result := db.Delete(&server_structs.ApiKey{}, "id = ?", id)
	if result.Error != nil {
		return errors.Wrap(result.Error, "failed to delete the API key")
	}
	if result.RowsAffected == 0 {
		return errors.New("API key not found")
	}
	// delete from cache so that we don't accidentally allow the deleted key to be used
	verifiedKeysCache.Delete(id)
	return nil
}

func ListApiKeys(db *gorm.DB) ([]server_structs.ApiKey, error) {
	var apiKeys []server_structs.ApiKey
	result := db.Select([]string{"id", "name", "created_at", "created_by", "expires_at", "scopes"}).Find(&apiKeys)
	if result.Error != nil {
		return nil, errors.Wrap(result.Error, "failed to list API keys")
	}

	return apiKeys, nil
}

func GetApiKeyCreator(db *gorm.DB, id string) (string, error) {
	var apiKey server_structs.ApiKey
	result := db.First(&apiKey, "id = ?", id)
	if result.Error != nil {
		return "", errors.Wrap(result.Error, "failed to get the API key creator")
	}
	return apiKey.CreatedBy, nil
}
