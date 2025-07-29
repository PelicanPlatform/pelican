package database

import "time"

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
	Name        string `gorm:"not null;uniqueIndex:idx_owner_issuer_name"`
	Description string
	OwnerSub    string               `gorm:"not null;uniqueIndex:idx_owner_issuer_name"`
	OwnerIssuer string               `gorm:"not null;uniqueIndex:idx_owner_issuer_name"`
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
	AddedBySub   string    `gorm:"not null"`
	AddedAt      time.Time `gorm:"not null;default:CURRENT_TIMESTAMP"`
}

type CollectionACL struct {
	CollectionID    string    `gorm:"primaryKey"`
	PrincipalSub    string    `gorm:"primaryKey"`
	PrincipalIssuer string    `gorm:"primaryKey;not null"`
	Role            AclRole   `gorm:"primaryKey;not null"`
	GrantedBySub    string    `gorm:"not null"`
	GrantedAt       time.Time `gorm:"not null;default:CURRENT_TIMESTAMP"`
	ExpiresAt       *time.Time
}

type CollectionMetadata struct {
	CollectionID string `gorm:"primaryKey"`
	Key          string `gorm:"primaryKey;not null"`
	Value        string `gorm:"not null"`
}
