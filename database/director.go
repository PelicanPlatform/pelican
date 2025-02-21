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

var DirectorDB *gorm.DB

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

	if !token.ExpiresAt.IsZero() && time.Now().After(token.ExpiresAt) {
		return false, nil, errors.New("Token has expired")
	}

	err = bcrypt.CompareHashAndPassword([]byte(token.HashedValue), []byte(secret))
	if err != nil {
		return false, nil, errors.New("Invalid API token")
	}

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
	}
	verifiedKeysCache.Set(id, cached, cacheTTL)
	return true, cached.Capabilities, nil
}

func CreateApiKey(name, createdBy, scopes string, expiration time.Time) (string, error) {
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
			ExpiresAt:   expiration,
			CreatedAt:   time.Now(),
			CreatedBy:   createdBy,
		}
		result := DirectorDB.Create(apiKey)
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

func DeleteApiKey(id string, verifiedKeysCache *ttlcache.Cache[string, server_structs.ApiKeyCached]) error {
	result := DirectorDB.Delete(&server_structs.ApiKey{}, "id = ?", id)
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
