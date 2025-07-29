package database

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"gorm.io/gorm"
)

type Visibility string

const (
	VisibilityPrivate Visibility = "private"
	VisibilityPublic  Visibility = "public"
)

type AclRole string

const (
	AclRoleRead  AclRole = "read"
	AclRoleWrite AclRole = "write"
	AclRoleOwner AclRole = "owner"
)

type Collection struct {
	ID          string `gorm:"primaryKey"`
	Name        string `gorm:"not null;uniqueIndex:idx_owner_name"`
	Description string
	Owner       string               `gorm:"not null;uniqueIndex:idx_owner_name"`
	Visibility  Visibility           `gorm:"not null;default:private"`
	CreatedAt   time.Time            `gorm:"not null;default:CURRENT_TIMESTAMP"`
	UpdatedAt   time.Time            `gorm:"not null;default:CURRENT_TIMESTAMP"`
	Members     []CollectionMember   `gorm:"foreignKey:CollectionID"`
	ACLs        []CollectionACL      `gorm:"foreignKey:CollectionID"`
	Metadata    []CollectionMetadata `gorm:"foreignKey:CollectionID"`
}

type CollectionMember struct {
	CollectionID string    `gorm:"primaryKey"`
	ObjectURL    string    `gorm:"primaryKey"` // full pelican:// URL
	AddedBy      string    `gorm:"not null"`
	AddedAt      time.Time `gorm:"not null;default:CURRENT_TIMESTAMP"`
}

type CollectionACL struct {
	CollectionID string    `gorm:"primaryKey"`
	Principal    string    `gorm:"primaryKey"`
	Role         AclRole   `gorm:"primaryKey;not null"`
	GrantedBy    string    `gorm:"not null"`
	GrantedAt    time.Time `gorm:"not null;default:CURRENT_TIMESTAMP"`
	ExpiresAt    *time.Time
}

type CollectionMetadata struct {
	CollectionID string `gorm:"primaryKey"`
	Key          string `gorm:"primaryKey;not null"`
	Value        string `gorm:"not null"`
}

func generateSlug() (string, error) {
	slug := make([]byte, 16)
	_, err := rand.Read(slug)
	if err != nil {
		return "", err
	}
	slugStr := hex.EncodeToString(slug)
	slugStr = slugStr[:8]
	return slugStr, nil
}

func CreateCollection(db *gorm.DB, name, description, owner string, visibility Visibility) (*Collection, error) {
	// generate a human readable slug
	// using random bytes
	slug, err := generateSlug()
	if err != nil {
		return nil, err
	}

	collection := &Collection{
		ID:          slug,
		Name:        name,
		Description: description,
		Owner:       owner,
		Visibility:  visibility,
	}

	result := db.Create(collection)
	if result.Error != nil {
		return nil, result.Error
	}

	return collection, nil
}

func CreateCollectionWithMetadata(db *gorm.DB, name, description, owner string, visibility Visibility, metadata map[string]string) (*Collection, error) {
	slug, err := generateSlug()
	if err != nil {
		return nil, err
	}

	collection := &Collection{
		ID:          slug,
		Name:        name,
		Description: description,
		Owner:       owner,
		Visibility:  visibility,
	}

	err = db.Transaction(func(tx *gorm.DB) error {
		if result := tx.Create(collection); result.Error != nil {
			return result.Error
		}

		if len(metadata) > 0 {
			metadataEntries := make([]CollectionMetadata, 0, len(metadata))
			for k, v := range metadata {
				metadataEntries = append(metadataEntries, CollectionMetadata{
					CollectionID: collection.ID,
					Key:          k,
					Value:        v,
				})
			}
			if result := tx.Create(&metadataEntries); result.Error != nil {
				return result.Error
			}
		}

		// Also create the owner ACL
		ownerAcl := &CollectionACL{
			CollectionID: collection.ID,
			Principal:    owner,
			Role:         AclRoleOwner,
			GrantedBy:    owner,
		}
		if result := tx.Create(ownerAcl); result.Error != nil {
			return result.Error
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return collection, nil
}
