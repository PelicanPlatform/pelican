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
)

var DirectorDB *gorm.DB

type (
	ApiKey struct {
		ID          string `gorm:"primaryKey;column:id;type:text;not null;unique"`
		Name        string `gorm:"column:name;type:text"`
		HashedValue string `gorm:"column:hashed_value;type:text;not null"`
		Scopes      string `gorm:"column:scopes;type:text"`
		ExpiresAt   time.Time
		CreatedAt   time.Time
		CreatedBy   string `gorm:"column:created_by;type:text"`
	}

	ApiKeyCached struct {
		Token        string // "$ID.$SECRET_IN_HEX" string form
		Capabilities []string
	}
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

func VerifyApiKey(apiKey string, verifiedKeysCache *ttlcache.Cache[string, ApiKeyCached]) (bool, []string, error) {
	item := verifiedKeysCache.Get(apiKey)
	if item != nil {
		// Cache hit
		return true, item.Value().Capabilities, nil
	}
	parts := strings.Split(apiKey, ".")
	if len(parts) != 2 {
		return false, nil, errors.New("invalid API key format")
	}
	id := parts[0]
	secretHex := parts[1]

	item := verifiedKeysCache.Get(id)
	if item != nil {
		// Cache hit
		return true, item.Value().Capabilities, nil
	}

	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		return false, nil, errors.Wrap(err, "failed to decode the secret")
	}

	var token ApiKey
	result := DirectorDB.First(&token, "id = ?", id)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return false, nil, nil // token not found
		}
		return false, nil, errors.Wrap(result.Error, "failed to retrieve the API key")
	}

	if !token.ExpiresAt.IsZero() && time.Now().After(token.ExpiresAt) {
		return false, nil, nil
	}

	err = bcrypt.CompareHashAndPassword([]byte(token.HashedValue), []byte(secret))
	if err != nil {
		return false, nil, nil
	}

	cacheTTL := ttlcache.DefaultTTL
	if !token.ExpiresAt.IsZero() {
		timeUntilExpiration := time.Until(token.ExpiresAt)
		if timeUntilExpiration < cacheTTL {
			cacheTTL = timeUntilExpiration
		}
	}

	cached := ApiKeyCached{
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

		apiKey := ApiKey{
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

func DeleteApiKey(id string, verifiedKeysCache *ttlcache.Cache[string, ApiKeyCached]) error {
	result := DirectorDB.Delete(&ApiKey{}, "id = ?", id)
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
