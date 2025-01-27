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

type ApiKey struct {
	ID          string `gorm:"primaryKey;column:id;type:text;not null;unique"`
	Name        string `gorm:"column:name;type:text"`
	HashedValue string `gorm:"column:hashed_value;type:text;not null"`
	Scopes      string `gorm:"column:scopes;type:text"`
	ExpiresAt   time.Time
	CreatedAt   time.Time
	CreatedBy   string `gorm:"column:created_by;type:text"`
}

func generateSecret(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func generateTokenID(secret string) string {
	hash := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(hash[:])[:5]
}

func VerifyApiKey(apiKey string, verifiedKeysCache *ttlcache.Cache[string, ApiKey]) (bool, error) {
	parts := strings.Split(apiKey, ".")
	if len(parts) != 2 {
		return false, errors.New("invalid API key format")
	}
	id := parts[0]
	secret := parts[1]

	item := verifiedKeysCache.Get(id)
	if item != nil {
		cachedToken := item.Value()
		beforeExpiration := time.Now().Before(cachedToken.ExpiresAt)
		matches := bcrypt.CompareHashAndPassword([]byte(cachedToken.HashedValue), []byte(secret)) == nil
		if beforeExpiration && matches {
			return true, nil
		}
	}

	var token ApiKey
	result := DirectorDB.First(&token, "id = ?", id)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return false, nil // token not found
		}
		return false, errors.Wrap(result.Error, "failed to retrieve the API key")
	}

	if time.Now().After(token.ExpiresAt) {
		return false, nil
	}

	err := bcrypt.CompareHashAndPassword([]byte(token.HashedValue), []byte(secret))
	if err != nil {
		return false, nil
	}

	verifiedKeysCache.Set(id, token, ttlcache.DefaultTTL)
	return true, nil
}

func CreateApiKey(name, createdBy, scopes string) (string, error) {
	expiresAt := time.Now().Add(time.Hour * 24 * 30) // 30 days
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
			ExpiresAt:   expiresAt,
			CreatedAt:   time.Now(),
			CreatedBy:   createdBy,
		}
		result := DirectorDB.Create(apiKey)
		if result.Error != nil {
			isConstraintError := result.Error.Error() == "UNIQUE constraint failed: tokens.id"
			if !isConstraintError {
				return "", errors.Wrap(result.Error, "failed to create a new API key")
			}
			// If the ID is already taken, try again
			continue
		}
		return fmt.Sprintf("%s.%s", id, secret), nil
	}
}

func DeleteApiKey(id string, verifiedKeysCache *ttlcache.Cache[string, ApiKey]) error {
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
