package database

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"time"

	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/token_scopes"
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

var (
	ScopeToRole map[token_scopes.TokenScope][]AclRole = map[token_scopes.TokenScope][]AclRole{
		token_scopes.Collection_Read:   {AclRoleRead, AclRoleWrite, AclRoleOwner},
		token_scopes.Collection_Modify: {AclRoleWrite, AclRoleOwner},
		token_scopes.Collection_Delete: {AclRoleOwner},
	}
)

type Collection struct {
	ID          string               `gorm:"primaryKey" json:"id"`
	Name        string               `gorm:"not null;uniqueIndex:idx_owner_name" json:"name"`
	Description string               `json:"description"`
	Owner       string               `gorm:"not null;uniqueIndex:idx_owner_name" json:"owner"`
	Visibility  Visibility           `gorm:"not null;default:private" json:"visibility"`
	CreatedAt   time.Time            `gorm:"not null;default:CURRENT_TIMESTAMP" json:"created_at"`
	UpdatedAt   time.Time            `gorm:"not null;default:CURRENT_TIMESTAMP" json:"updated_at"`
	Members     []CollectionMember   `gorm:"foreignKey:CollectionID" json:"members"`
	ACLs        []CollectionACL      `gorm:"foreignKey:CollectionID" json:"acls"`
	Metadata    []CollectionMetadata `gorm:"foreignKey:CollectionID" json:"metadata"`
}

type CollectionMember struct {
	CollectionID string    `gorm:"primaryKey" json:"collection_id"`
	ObjectURL    string    `gorm:"primaryKey" json:"object_url"` // full pelican:// URL
	AddedBy      string    `gorm:"not null" json:"added_by"`
	AddedAt      time.Time `gorm:"not null;default:CURRENT_TIMESTAMP" json:"added_at"`
}

type CollectionACL struct {
	CollectionID string     `gorm:"primaryKey" json:"collection_id"`
	Principal    string     `gorm:"primaryKey" json:"principal"`
	Role         AclRole    `gorm:"primaryKey;not null" json:"role"`
	GrantedBy    string     `gorm:"not null" json:"granted_by"`
	GrantedAt    time.Time  `gorm:"not null;default:CURRENT_TIMESTAMP" json:"granted_at"`
	ExpiresAt    *time.Time `json:"expires_at"`
}

type CollectionMetadata struct {
	CollectionID string `gorm:"primaryKey" json:"collection_id"`
	Key          string `gorm:"primaryKey;not null" json:"key"`
	Value        string `gorm:"not null" json:"value"`
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

func GetCollection(db *gorm.DB, id string, accessor string) (*Collection, error) {
	collection := &Collection{}
	if result := db.Preload("Members").Preload("ACLs").Preload("Metadata").Where("id = ?", id).First(collection); result.Error != nil {
		return nil, result.Error
	}

	if collection.Visibility == VisibilityPublic {
		return collection, nil
	}

	err := validateACL(collection, accessor, token_scopes.Collection_Read)
	if err != nil {
		return nil, err
	}

	return collection, nil
}

func AddCollectionMembers(db *gorm.DB, id string, members []string, addedBy string) error {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return result.Error
	}

	if err := validateACL(collection, addedBy, token_scopes.Collection_Modify); err != nil {
		return err
	}

	records := make([]CollectionMember, 0, len(members))
	for _, member := range members {
		records = append(records, CollectionMember{
			CollectionID: id,
			ObjectURL:    member,
			AddedBy:      addedBy,
		})
	}
	err := db.Transaction(func(tx *gorm.DB) error {
		if result := tx.Create(&records); result.Error != nil {
			return result.Error
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func validateACL(collection *Collection, accessor string, scope token_scopes.TokenScope) error {
	roles, ok := ScopeToRole[scope]
	if !ok {
		return fmt.Errorf("invalid scope: %s", scope.String())
	}

	// for each acl, check if the accessor is the principal and has the required role
	for _, acl := range collection.ACLs {
		if acl.Principal == accessor && slices.Contains(roles, acl.Role) {
			return nil
		}
	}

	return fmt.Errorf("access denied. accessor '%s' does not have required scope '%s' for collection '%s'", accessor, scope.String(), collection.ID)
}
