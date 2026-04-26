package database

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/token_scopes"
)

var (
	ErrForbidden = errors.New("forbidden")
	// ErrReservedGroupPrefix indicates a requested group name collides with the
	// reserved prefix used for automatically managed personal groups.
	ErrReservedGroupPrefix = errors.New("reserved group name prefix 'user-'")
	// ErrInvalidPassword is returned by VerifyLocalUserPassword when the user
	// exists but has no local password configured or the password doesn't match.
	ErrInvalidPassword = errors.New("invalid username or password")
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
	Namespace   string               `gorm:"not null" json:"namespace"`
	Visibility  Visibility           `gorm:"not null;default:private" json:"visibility"`
	CreatedAt   time.Time            `gorm:"not null;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt   time.Time            `gorm:"not null;default:CURRENT_TIMESTAMP" json:"updatedAt"`
	Members     []CollectionMember   `gorm:"foreignKey:CollectionID" json:"members"`
	ACLs        []CollectionACL      `gorm:"foreignKey:CollectionID" json:"acls"`
	Metadata    []CollectionMetadata `gorm:"foreignKey:CollectionID" json:"metadata"`
}

type CollectionMember struct {
	CollectionID string    `gorm:"primaryKey" json:"collectionId"`
	ObjectURL    string    `gorm:"primaryKey" json:"objectUrl"` // full pelican:// URL
	AddedBy      string    `gorm:"not null" json:"createdBy"`
	AddedAt      time.Time `gorm:"not null;default:CURRENT_TIMESTAMP" json:"createdAt"`
}

type CollectionACL struct {
	CollectionID string     `gorm:"primaryKey" json:"collectionId"`
	GroupID      string     `gorm:"primaryKey" json:"groupId"`
	Role         AclRole    `gorm:"primaryKey;not null" json:"role"`
	GrantedBy    string     `gorm:"not null" json:"createdBy"`
	GrantedAt    time.Time  `gorm:"not null;default:CURRENT_TIMESTAMP" json:"createdAt"`
	ExpiresAt    *time.Time `json:"expiresAt"`
}

type CollectionMetadata struct {
	CollectionID string `gorm:"primaryKey" json:"collectionId"`
	Key          string `gorm:"primaryKey;not null" json:"key"`
	Value        string `gorm:"not null" json:"value"`
}

type UserStatus string

const (
	UserStatusActive   UserStatus = "active"
	UserStatusInactive UserStatus = "inactive"
)

// User is the canonical user record. Four concepts live on this row and
// they are intentionally distinct — code that conflates them is a bug.
//
//	Field         Purpose                              Mutability         Used for authz?
//	-----         -------                              ----------         ---------------
//	ID            Opaque internal primary key.         Immutable;         NO — never.
//	              Auto-generated; never reused —       never reused
//	              soft-deletes flag the row, they      (delete is a
//	              do not actually remove it.           soft delete).
//
//	              ID DOES leak into URLs and JSON
//	              responses (json:"id"). The design
//	              doc said "should NOT be presented
//	              to the web interface"; the
//	              practical posture this codebase
//	              has settled on is "ID is a routing
//	              handle, never a permission grant."
//	              Specifically:
//	                - admin lists (Server.UIAdminUsers
//	                  et al) are matched against
//	                  Username only — never ID.
//	                - The user_id claim in the login
//	                  cookie is used purely as a
//	                  lookup key (GetUserByID) for
//	                  re-validating the row exists
//	                  and is active. It is NOT
//	                  matched against config or
//	                  compared with any other ID.
//	                - The cookie's signature is
//	                  verified against the local key
//	                  AND the issuer/audience are
//	                  pinned to Server.ExternalWebUrl,
//	                  so an attacker can't forge a
//	                  cookie carrying an arbitrary
//	                  user_id.
//	              An ID value is therefore safe to
//	              embed in URLs / SWR keys / log
//	              lines: knowing it grants no
//	              authority by itself.
//
//	Username      Authorization handle. Compared       Admin-controlled   YES.
//	              against admin lists, group           after first login.
//	              memberships, etc.                    Bootstrapped from
//	                                                   IdP at first login
//	                                                   per the configured
//	                                                   claim list.
//
//	DisplayName   Human label for the UI.              Self-editable;     No.
//	                                                   refreshed from the
//	                                                   IdP on each login.
//
//	Sub / Issuer  Linked OIDC identity for *login*     Add/remove as a    No — never.
//	              only. Multiple identities per user   linked identity
//	              live in user_identities (this row    via /identities;
//	              is the primary linkage).             not edited inline.
//
// Anything that looks like "use sub for permissions" or "rename the user
// based on the IdP claim every login" is wrong — see LookupOrBootstrapUser
// for the correct first-login / return-visit flow.
type User struct {
	ID           string         `gorm:"primaryKey" json:"id"`
	Username     string         `gorm:"not null;uniqueIndex:idx_user_issuer" json:"username"`
	Sub          string         `gorm:"not null;uniqueIndex:idx_user_sub_issuer" json:"sub"`
	Issuer       string         `gorm:"not null;uniqueIndex:idx_user_issuer;uniqueIndex:idx_user_sub_issuer" json:"issuer"`
	Status       UserStatus     `gorm:"not null;default:active" json:"status"`
	LastLoginAt  *time.Time     `json:"lastLoginAt"`
	DisplayName string     `gorm:"not null;default:''" json:"displayName"`
	AUPVersion  string     `gorm:"not null;default:''" json:"aupVersion"`
	AUPAgreedAt *time.Time `json:"aupAgreedAt"`
	// HasPassword is a derived JSON-only field — populated in AfterFind
	// via a side query that reads only a boolean projection of the
	// password_hash column. The hash itself never lives on this struct;
	// see database/credentials.go for the full reasoning. Not stored.
	HasPassword bool `gorm:"-" json:"hasPassword"`
	// CreatedBy is the user ID of whoever caused this record to exist,
	// or one of the sentinels CreatorSelfEnrolled / CreatorUnknown. See
	// the Creator struct for the audit fields recorded together at
	// every create site.
	CreatedBy           string     `gorm:"not null;default:'unknown'" json:"createdBy"`
	CreatorAuthMethod   AuthMethod `gorm:"not null;default:''" json:"creatorAuthMethod"`
	CreatorAuthMethodID string     `gorm:"not null;default:''" json:"creatorAuthMethodId,omitempty"`
	CreatedAt           time.Time  `gorm:"not null;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt           time.Time  `gorm:"not null;default:CURRENT_TIMESTAMP" json:"updatedAt"`
	// DeletedAt is the soft-delete tombstone. GORM auto-excludes rows where
	// it is non-NULL from ordinary queries; callers needing to surface
	// deleted users (audit, history) must use db.Unscoped(). See the
	// 20260425120000_user_soft_delete migration and the contract comment
	// above for the why.
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

// HasLocalPassword reports whether the user can log in via username/password.
// Backed by the same projection populated into HasPassword by AfterFind.
func (u *User) HasLocalPassword() bool {
	return u != nil && u.HasPassword
}

// AfterFind populates the derived HasPassword field on every User load
// by issuing a single boolean-projection query against the users table.
// Done in the hook (rather than at each call site) so handlers can't
// forget — every code path that reads a User out of the DB sees the
// flag set correctly. The hash itself never enters the User struct;
// see database/credentials.go for the security contract.
//
// This adds one extra round-trip per loaded User. Acceptable for the
// admin-side surfaces this powers; if hot lists become a problem,
// switch them to usersWithPassword for a single batched query.
func (u *User) AfterFind(tx *gorm.DB) error {
	if u.ID == "" {
		return nil
	}
	has, err := userHasPassword(tx, u.ID)
	if err != nil {
		return err
	}
	u.HasPassword = has
	return nil
}

type AdminType string

const (
	AdminTypeUser  AdminType = "user"
	AdminTypeGroup AdminType = "group"
)

// Group mirrors the User contract for the four-concept model:
//
//   - Name is the *machine-readable* handle: admin-controlled, used in
//     policy strings (admin-group lists, ACL grants, configuration).
//   - DisplayName is a *human label*: owner-editable, used in the UI.
//   - ID is an opaque internal primary key.
//
// See ValidateIdentifier for the character class enforced on Name.
// DisplayName has the laxer ValidateDisplayName ruleset.
type Group struct {
	ID                  string     `gorm:"primaryKey" json:"id"`
	Name                string     `gorm:"not null;unique" json:"name"`
	DisplayName         string     `gorm:"not null;default:''" json:"displayName"`
	Description         string     `json:"description"`
	CreatedBy           string     `gorm:"not null" json:"createdBy"`
	CreatorAuthMethod   AuthMethod `gorm:"not null;default:''" json:"creatorAuthMethod"`
	CreatorAuthMethodID string     `gorm:"not null;default:''" json:"creatorAuthMethodId,omitempty"`
	OwnerID             string     `gorm:"not null;default:''" json:"ownerId"`
	AdminID             string     `gorm:"not null;default:''" json:"adminId"`
	AdminType           AdminType  `gorm:"not null;default:''" json:"adminType"`
	CreatedAt           time.Time  `gorm:"not null;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt   time.Time     `gorm:"not null;default:CURRENT_TIMESTAMP" json:"updatedAt"`
	Members     []GroupMember `gorm:"foreignKey:GroupID" json:"members"`
}

type GroupMember struct {
	GroupID string    `gorm:"primaryKey" json:"groupId"`
	UserID  string    `gorm:"primaryKey" json:"userId"`
	User    User      `gorm:"foreignKey:UserID" json:"user"`
	AddedBy string    `gorm:"not null" json:"createdBy"`
	AddedAt time.Time `gorm:"not null;default:CURRENT_TIMESTAMP" json:"createdAt"`
}

// InviteKind discriminates what an invite link grants when redeemed.
//
//   - InviteKindGroup: redeem-time, the *caller's* user is added to GroupID.
//     Caller must be authenticated (we need a user to add to the group).
//   - InviteKindPassword: redeem-time, the link sets the password for
//     TargetUserID. Caller need NOT be authenticated — possession of the
//     token IS the credential, by design (this is the "click the link in
//     the email to set your password" pattern). Admins use this to onboard
//     accounts without ever learning the user's password.
type InviteKind string

const (
	InviteKindGroup    InviteKind = "group"
	InviteKindPassword InviteKind = "password"
)

// AuthMethod records how the *creator* of a record was authenticated at
// the moment they created it. Useful for audit trails and incident
// response: "who created this record, and were they sitting at the web
// UI or driving it from a script?" Recorded on invite-links, Users, and
// Groups (and any future record we want to audit similarly).
type AuthMethod string

const (
	AuthMethodWebCookie AuthMethod = "web-cookie"
	AuthMethodAPIToken  AuthMethod = "api-token"
	AuthMethodBearerJWT AuthMethod = "bearer-jwt"
)

// Sentinel values for User.CreatedBy when no real creator user ID
// applies. Per the design contract these are reserved strings, not
// foreign-key references.
const (
	// CreatorSelfEnrolled marks accounts auto-created on the user's
	// first OIDC sign-in. There is no other user "responsible for"
	// the account in that case — the user enrolled themselves by
	// authenticating.
	CreatorSelfEnrolled = "self-enrolled"
	// CreatorUnknown is the backfill value for rows that predate the
	// created_by column. Treat as "we don't know" — not as a security
	// claim about the account.
	CreatorUnknown = "unknown"
)

// Creator bundles the audit fields recorded at every record-creation
// site. Instead of pushing three positional parameters through every
// signature, callers construct this once (typically in the HTTP handler
// via captureAuthMethod) and hand it to the DB layer. CreatorSelf and
// CreatorUnknownContext are convenience constructors for the
// common no-attributable-user cases.
type Creator struct {
	UserID       string
	AuthMethod   AuthMethod
	AuthMethodID string
}

// CreatorSelf returns a Creator marking a record as self-enrolled — the
// user authenticated themselves into existence (OIDC first login).
func CreatorSelf() Creator { return Creator{UserID: CreatorSelfEnrolled} }

// GroupInviteLink — historical name; this row now backs *every* kind of
// invite link, not just group-join. See InviteKind.
//
// The unified schema was chosen over per-kind tables because every kind
// shares the same ~12 columns (token + lifecycle + audit) and only
// kind-specific link target differs (GroupID vs TargetUserID).
//
// Type alias `InviteLink` is the preferred name for new code.
type GroupInviteLink struct {
	ID          string     `gorm:"primaryKey" json:"id"`
	Kind        InviteKind `gorm:"not null;default:'group';index:idx_invite_links_kind" json:"kind"`
	// GroupID is set when Kind == InviteKindGroup. Empty otherwise.
	GroupID string `gorm:"not null;default:''" json:"groupId"`
	// TargetUserID is set when Kind == InviteKindPassword. Empty otherwise.
	// (For group invites the user is whoever redeems; for password invites
	// the user is fixed at link creation time and the redeemer must not be
	// allowed to set a different account's password.)
	TargetUserID string `gorm:"not null;default:'';index:idx_invite_links_target_user" json:"targetUserId"`
	HashedToken  string `gorm:"column:invite_token;not null;unique" json:"-"`
	// TokenPrefix is the first few characters of the *plaintext* token,
	// captured at mint time. It is NOT a credential — too narrow to brute
	// force into the bcrypt hash — but is enough to label, sort, and
	// disambiguate live invites in admin UIs and CLI listings.
	TokenPrefix string `gorm:"column:token_prefix;not null;default:''" json:"tokenPrefix"`
	CreatedBy   string `gorm:"not null" json:"createdBy"`
	// AuthMethod / AuthMethodID describe how CreatedBy was authenticated
	// when this link was minted (web cookie vs API token id, ...). See
	// AuthMethod constants above.
	AuthMethod   AuthMethod `gorm:"not null;default:''" json:"authMethod"`
	AuthMethodID string     `gorm:"not null;default:''" json:"authMethodId,omitempty"`
	CreatedAt    time.Time  `gorm:"not null;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt    time.Time  `gorm:"not null;default:CURRENT_TIMESTAMP" json:"updatedAt"`
	ExpiresAt    time.Time  `gorm:"not null" json:"expiresAt"`
	IsSingleUse  bool       `gorm:"not null;default:false" json:"isSingleUse"`
	RedeemedBy   string     `gorm:"not null;default:''" json:"redeemedBy"`
	RedeemedAt   *time.Time `json:"redeemedAt"`
	Revoked      bool       `gorm:"not null;default:false" json:"revoked"`
}

// InviteLink is the preferred name for the row above. Use it in new code;
// older call sites still reference GroupInviteLink for backwards compat.
type InviteLink = GroupInviteLink

type UserIdentity struct {
	ID     string `gorm:"primaryKey" json:"id"`
	UserID string `gorm:"not null;uniqueIndex:idx_user_identities_user_issuer" json:"userId"`
	// Sub + Issuer is unique globally (no two users share an identity)
	// AND user_id + Issuer is unique (one identity per issuer per user).
	// Both invariants matter; both are enforced by indexes.
	Sub       string    `gorm:"not null;uniqueIndex:idx_identity_sub_issuer" json:"sub"`
	Issuer    string    `gorm:"not null;uniqueIndex:idx_identity_sub_issuer;uniqueIndex:idx_user_identities_user_issuer" json:"issuer"`
	CreatedAt time.Time `gorm:"not null;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt time.Time `gorm:"not null;default:CURRENT_TIMESTAMP" json:"updatedAt"`
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

func CreateCollection(db *gorm.DB, name, description, owner, namespace string, visibility Visibility) (*Collection, error) {
	slug, err := generateSlug()
	if err != nil {
		return nil, err
	}

	collection := &Collection{
		ID:          slug,
		Name:        name,
		Description: description,
		Owner:       owner,
		Namespace:   namespace,
		Visibility:  visibility,
	}

	err = db.Transaction(func(tx *gorm.DB) error {
		if result := tx.Create(collection); result.Error != nil {
			return result.Error
		}

		// Also create the owner ACL for the owner's primary group
		ownerGroup := "user-" + owner
		ownerAcl := &CollectionACL{
			CollectionID: collection.ID,
			GroupID:      ownerGroup,
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

func CreateCollectionWithMetadata(db *gorm.DB, name, description, owner, namespace string, visibility Visibility, metadata map[string]string) (*Collection, error) {
	slug, err := generateSlug()
	if err != nil {
		return nil, err
	}

	collection := &Collection{
		ID:          slug,
		Name:        name,
		Description: description,
		Owner:       owner,
		Namespace:   namespace,
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

		// Also create the owner ACL for the owner's primary group
		ownerGroup := "user-" + owner
		ownerAcl := &CollectionACL{
			CollectionID: collection.ID,
			GroupID:      ownerGroup,
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

func ListCollections(db *gorm.DB, user string, groups []string) ([]Collection, error) {
	collections := []Collection{}
	// Every user is part of their own user group, ensure this is in the slice
	userGroup := "user-" + user
	if !slices.Contains(groups, userGroup) {
		groups = append(groups, userGroup)
	}
	// First, get all public collections.
	if result := db.Where("visibility = ?", VisibilityPublic).Find(&collections); result.Error != nil {
		return nil, result.Error
	}
	// Then, get all collections for which the user has a read ACL.
	var aclCollections []Collection
	if result := db.
		Joins("JOIN collection_acls ON collections.id = collection_acls.collection_id").
		Where("collection_acls.group_id IN ? AND collection_acls.role IN ?", groups, ScopeToRole[token_scopes.Collection_Read]).
		Find(&aclCollections); result.Error != nil {
		return nil, result.Error
	}
	// Merge the two lists, avoiding duplicates.
	for _, aclCol := range aclCollections {
		found := false
		for _, pubCol := range collections {
			if aclCol.ID == pubCol.ID {
				found = true
				break
			}
		}
		if !found {
			collections = append(collections, aclCol)
		}
	}
	return collections, nil
}

func GetCollection(db *gorm.DB, id string, user string, groups []string) (*Collection, error) {
	collection := &Collection{}
	if result := db.Preload("Members").Preload("ACLs").Preload("Metadata").Where("id = ?", id).First(collection); result.Error != nil {
		return nil, result.Error
	}

	if collection.Visibility == VisibilityPublic {
		return collection, nil
	}

	err := validateACL(collection, user, groups, token_scopes.Collection_Read)
	if err != nil {
		return nil, err
	}

	return collection, nil
}

func GetCollectionMembers(db *gorm.DB, id, user string, groups []string, since *time.Time, limit int) ([]CollectionMember, error) {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return nil, result.Error
	}

	err := validateACL(collection, user, groups, token_scopes.Collection_Read)
	if err != nil {
		return nil, err
	}

	members := []CollectionMember{}
	query := db.Where("collection_id = ?", id)
	if since != nil {
		query = query.Where("added_at > ?", *since)
	}
	if limit > 0 {
		query = query.Limit(limit)
	}

	if result := query.Find(&members); result.Error != nil {
		return nil, result.Error
	}
	return members, nil
}

func GetCollectionMetadata(db *gorm.DB, id, user string, groups []string) ([]CollectionMetadata, error) {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return nil, result.Error
	}

	err := validateACL(collection, user, groups, token_scopes.Collection_Read)
	if err != nil {
		return nil, err
	}

	metadata := []CollectionMetadata{}
	if result := db.Where("collection_id = ?", id).Find(&metadata); result.Error != nil {
		return nil, result.Error
	}
	return metadata, nil
}

func GetCollectionAcls(db *gorm.DB, id, user string, groups []string) ([]CollectionACL, error) {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return nil, result.Error
	}

	// The spec says that owners and writers should be able to see the ACLs.
	// We can reuse the Collection_Modify scope for this.
	err := validateACL(collection, user, groups, token_scopes.Collection_Modify)
	if err != nil {
		return nil, err
	}

	return collection.ACLs, nil
}

func GrantCollectionAcl(db *gorm.DB, id, user string, groups []string, groupId string, role AclRole, expiresAt *time.Time, isAdmin bool) error {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return result.Error
	}

	if !isAdmin {
		err := validateACL(collection, user, groups, token_scopes.Collection_Delete)
		if err != nil {
			return err
		}
	}

	// Resolve the provided group identifier (which may be the internal slug returned
	// by the create-group endpoint) to the human-readable group *name*.  The group
	// *name* is what’s shipped in the `wlcg.groups` claim of the JWT and therefore
	// what we should persist in the ACL for later comparisons during authorization.
	var grp Group
	if err := db.First(&grp, "id = ?", groupId).Error; err == nil {
		// We found the group by its slug; switch to using the group name.
		groupId = grp.Name
	} else if errors.Is(err, gorm.ErrRecordNotFound) {
		// It's possible the caller already provided the group *name*; try to look
		// it up by name to verify it exists (and to ensure a consistent casing).
		if err2 := db.First(&grp, "name = ?", groupId).Error; err2 == nil {
			groupId = grp.Name // Adopt the canonical name from the DB.
		} // else: leave groupId unchanged – we’ll trust the caller.
	} else {
		// Unexpected database error.
		return err
	}

	return db.Transaction(func(tx *gorm.DB) error {
		acl := CollectionACL{
			CollectionID: id,
			GroupID:      groupId,
			Role:         role,
			GrantedBy:    user,
			ExpiresAt:    expiresAt,
		}
		// Use OnConflict to either create or update the ACL
		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "collection_id"}, {Name: "group_id"}, {Name: "role"}},
			DoUpdates: clause.AssignmentColumns([]string{"granted_by", "expires_at"}),
		}).Create(&acl).Error
	})
}

func RevokeCollectionAcl(db *gorm.DB, id, user string, groups []string, groupId string, role AclRole, isAdmin bool) error {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return result.Error
	}

	if !isAdmin {
		err := validateACL(collection, user, groups, token_scopes.Collection_Delete)
		if err != nil {
			return err
		}
	}

	return db.Transaction(func(tx *gorm.DB) error {
		if result := tx.Where("collection_id = ? AND group_id = ? AND role = ?", id, groupId, role).Delete(&CollectionACL{}); result.Error != nil {
			return result.Error
		}
		return nil
	})
}

func UpsertCollectionMetadata(db *gorm.DB, id, user string, groups []string, key, value string, isAdmin bool) error {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return result.Error
	}

	if !isAdmin {
		err := validateACL(collection, user, groups, token_scopes.Collection_Modify)
		if err != nil {
			return err
		}
	}

	return db.Transaction(func(tx *gorm.DB) error {
		metadata := CollectionMetadata{
			CollectionID: id,
			Key:          key,
			Value:        value,
		}
		// Use OnConflict to either create or update the metadata
		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "collection_id"}, {Name: "key"}},
			DoUpdates: clause.AssignmentColumns([]string{"value"}),
		}).Create(&metadata).Error
	})
}

func DeleteCollectionMetadata(db *gorm.DB, id, user string, groups []string, key string, isAdmin bool) error {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return result.Error
	}

	if !isAdmin {
		err := validateACL(collection, user, groups, token_scopes.Collection_Modify)
		if err != nil {
			return err
		}
	}

	return db.Transaction(func(tx *gorm.DB) error {
		if result := tx.Where("collection_id = ? AND key = ?", id, key).Delete(&CollectionMetadata{}); result.Error != nil {
			return result.Error
		}
		return nil
	})
}

func UpdateCollection(db *gorm.DB, id, user string, groups []string, name, description *string, visibility *Visibility, isAdmin bool) error {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return result.Error
	}

	if !isAdmin {
		err := validateACL(collection, user, groups, token_scopes.Collection_Modify)
		if err != nil {
			return err
		}
	}

	updates := make(map[string]interface{})
	if name != nil {
		updates["name"] = *name
	}
	if description != nil {
		updates["description"] = *description
	}
	if visibility != nil {
		updates["visibility"] = *visibility
	}

	if len(updates) == 0 {
		return nil
	}

	return db.Model(&Collection{}).Where("id = ?", id).Updates(updates).Error
}

func AddCollectionMembers(db *gorm.DB, id string, members []string, addedBy string, groups []string, isAdmin bool) error {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return result.Error
	}

	if !isAdmin {
		err := validateACL(collection, addedBy, groups, token_scopes.Collection_Modify)
		if err != nil {
			return err
		}
	}

	// Enforce that each member belongs to the collection's namespace
	namespace := collection.Namespace
	for _, memberUrl := range members {
		purl, err := pelican_url.Parse(memberUrl, []pelican_url.ParseOption{}, []pelican_url.DiscoveryOption{})
		if err != nil {
			return fmt.Errorf("failed to parse member URL '%s': %w", memberUrl, err)
		}
		path := purl.Path
		if !strings.HasPrefix(path, namespace) {
			return fmt.Errorf("object URL '%s' does not belong to collection namespace '%s'", memberUrl, namespace)
		}
		// If the namespace prefix matches but is followed by additional characters that don't begin with '/', reject as well (e.g., '/test10')
		if len(path) > len(namespace) && path[len(namespace)] != '/' {
			return fmt.Errorf("object URL '%s' does not belong to collection namespace '%s'", memberUrl, namespace)
		}
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

func RemoveCollectionMembers(db *gorm.DB, id string, members []string, user string, groups []string, isAdmin bool) error {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return result.Error
	}

	if !isAdmin {
		err := validateACL(collection, user, groups, token_scopes.Collection_Modify)
		if err != nil {
			return err
		}
	}

	return db.Transaction(func(tx *gorm.DB) error {
		if result := tx.Where("collection_id = ? AND object_url IN ?", id, members).Delete(&CollectionMember{}); result.Error != nil {
			return result.Error
		}
		return nil
	})
}

func DeleteCollection(db *gorm.DB, id string, owner string, groups []string, isAdmin bool) error {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return result.Error
	}

	if !isAdmin {
		err := validateACL(collection, owner, groups, token_scopes.Collection_Delete)
		if err != nil {
			return err
		}
	}

	return db.Transaction(func(tx *gorm.DB) error {
		// delete all references to the collection
		if result := tx.Where("collection_id = ?", id).Delete(&CollectionMember{}); result.Error != nil {
			return result.Error
		}
		if result := tx.Where("collection_id = ?", id).Delete(&CollectionACL{}); result.Error != nil {
			return result.Error
		}
		if result := tx.Where("collection_id = ?", id).Delete(&CollectionMetadata{}); result.Error != nil {
			return result.Error
		}
		if result := tx.Delete(collection); result.Error != nil {
			return result.Error
		}
		return nil
	})
}

func validateACL(collection *Collection, user string, groups []string, scope token_scopes.TokenScope) error {
	roles, ok := ScopeToRole[scope]
	if !ok {
		return fmt.Errorf("invalid scope: %s", scope.String())
	}

	// Every user is part of their own user group, ensure this is in the slice
	userGroup := "user-" + user
	if !slices.Contains(groups, userGroup) {
		groups = append(groups, userGroup)
	}

	// for each acl, check if a user's group is the group in the ACL and has the required role
	for _, acl := range collection.ACLs {
		for _, group := range groups {
			if acl.GroupID == group && slices.Contains(roles, acl.Role) {
				if acl.ExpiresAt != nil && acl.ExpiresAt.Before(time.Now()) {
					return ErrForbidden
				}
				return nil
			}
		}
	}

	return ErrForbidden
}

func GetUserByUsername(db *gorm.DB, username string) (*User, error) {
	user := &User{}
	if err := db.Where("username = ?", username).First(user).Error; err != nil {
		return nil, err
	}
	return user, nil
}

// GetOrCreateUser is the htpasswd / init-code login path's "make sure
// this username has a DB row" helper. The user authenticated themselves
// (with a password / one-time code), so for the create case we mark the
// resulting row as self-enrolled. Callers should pass CreatorSelf() to
// be explicit; the function nonetheless ignores creator when the user
// already exists.
func GetOrCreateUser(db *gorm.DB, username string, sub string, issuer string, creator Creator) (*User, error) {
	user := &User{}
	err := db.Where("sub = ? AND issuer = ?", sub, issuer).First(user).Error
	if err == nil {
		// User found, return existing user
		return user, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	// User not found, create one
	return CreateUser(db, username, sub, issuer, creator)
}

func GetUserByID(db *gorm.DB, id string) (*User, error) {
	user := &User{}
	if err := db.First(user, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return user, nil
}

// CreateUser is the admin-driven path for creating a user record. The
// creator argument records who/how the request was made — see the
// Creator type. For the OIDC self-enrollment path use
// LookupOrBootstrapUser instead, which stamps CreatorSelf().
func CreateUser(db *gorm.DB, username string, sub string, issuer string, creator Creator) (*User, error) {
	if err := ValidateIdentifier(username); err != nil {
		return nil, err
	}
	slug, err := generateSlug()
	if err != nil {
		return nil, err
	}
	newUser := &User{
		ID:                  slug,
		Username:            username,
		Sub:                 sub,
		Issuer:              issuer,
		CreatedBy:           creatorOrUnknown(creator.UserID),
		CreatorAuthMethod:   creator.AuthMethod,
		CreatorAuthMethodID: creator.AuthMethodID,
	}
	if err := db.Create(newUser).Error; err != nil {
		// Check if the error is a unique constraint violation
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return nil, errors.New("user shares either username or (sub and iss) with another")
		}
		return nil, err
	}
	return newUser, nil
}

// creatorOrUnknown returns the supplied creator UserID, or the
// CreatorUnknown sentinel if it's empty. Empty creator means the call
// site forgot to pass one — preferable to record "we don't know" than
// to silently insert an empty string that violates the NOT NULL.
func creatorOrUnknown(s string) string {
	if s == "" {
		return CreatorUnknown
	}
	return s
}

// CreateLocalUser creates a user record intended for username/password
// authentication. The user's sub is set to the username and the issuer is the
// supplied local-issuer URL (typically Server.ExternalWebUrl). The row is
// created with no password — the only supported way to set a password is
// the admin-issued password-invite flow (see CreatePasswordInviteLink),
// so admins never see or pick a user's password.
func CreateLocalUser(db *gorm.DB, username, displayName, localIssuer string, creator Creator) (*User, error) {
	if err := ValidateIdentifier(username); err != nil {
		return nil, err
	}
	if err := ValidateDisplayName(displayName); err != nil {
		return nil, err
	}
	if localIssuer == "" {
		return nil, errors.New("local issuer URL is required for local users")
	}
	slug, err := generateSlug()
	if err != nil {
		return nil, err
	}
	user := &User{
		ID:                  slug,
		Username:            username,
		Sub:                 username,
		Issuer:              localIssuer,
		DisplayName:         displayName,
		CreatedBy:           creatorOrUnknown(creator.UserID),
		CreatorAuthMethod:   creator.AuthMethod,
		CreatorAuthMethodID: creator.AuthMethodID,
	}
	if err := db.Create(user).Error; err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return nil, errors.New("user shares either username or (sub and iss) with another")
		}
		return nil, err
	}
	return user, nil
}

func UpdateUser(db *gorm.DB, id string, username, sub, issuer *string) error {
	updates := make(map[string]interface{})
	if username != nil {
		if err := ValidateIdentifier(*username); err != nil {
			return err
		}
		updates["username"] = *username
	}
	if sub != nil {
		updates["sub"] = *sub
	}
	if issuer != nil {
		updates["issuer"] = *issuer
	}

	if len(updates) == 0 {
		return nil
	}

	if err := db.Model(&User{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return err
	}
	return nil
}

// BootstrapAdminAndBackfillOwners ensures the built-in "admin" user
// record exists and that every group has a real owner_id. Both are
// runtime concerns (the admin's primary identity is keyed off
// Server.ExternalWebUrl, which isn't known at SQL-migration time;
// existing groups created before owner_id existed need to be assigned
// to a concrete user). Safe to call on every startup; idempotent.
//
// The function is conservative: if Server.ExternalWebUrl isn't
// configured yet (e.g. brand-new install before the operator has set
// the externally-visible URL), it returns nil and skips both steps.
// They'll be retried the next time it's called.
func BootstrapAdminAndBackfillOwners(db *gorm.DB) error {
	externalURL := param.Server_ExternalWebUrl.GetString()
	if externalURL == "" {
		return nil
	}

	// 1. Ensure an admin user row exists. The admin "username" is
	//    the literal string "admin"; CheckAdmin in the web layer keys
	//    its bypass off that username, and the htpasswd login path has
	//    historically created the row with sub == username == "admin"
	//    and issuer == externalURL — so we follow the same shape.
	var admin User
	err := db.Where("username = ? AND issuer = ?", "admin", externalURL).First(&admin).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		slug, slugErr := generateSlug()
		if slugErr != nil {
			return slugErr
		}
		admin = User{
			ID:        slug,
			Username:  "admin",
			Sub:       "admin",
			Issuer:    externalURL,
			CreatedBy: CreatorSelfEnrolled,
		}
		if createErr := db.Create(&admin).Error; createErr != nil {
			// A unique-constraint conflict here means another goroutine
			// got there first; re-query and fall through.
			if !strings.Contains(createErr.Error(), "UNIQUE constraint failed") {
				return createErr
			}
			if reErr := db.Where("username = ? AND issuer = ?", "admin", externalURL).First(&admin).Error; reErr != nil {
				return reErr
			}
		}
	} else if err != nil {
		return err
	}

	// 2. Backfill ownerless groups onto the admin. Without this, the
	//    "no created_by fallback for visibility" rule (per the design
	//    doc) would render legacy groups invisible and unmanageable.
	if err := db.Model(&Group{}).
		Where("owner_id = ?", "").
		Update("owner_id", admin.ID).Error; err != nil {
		return err
	}

	return nil
}

// RenameUser is the supported way to change a user's Username. It
// enforces the design contract's invariant that for users authenticated
// against the *internal* issuer (i.e. local password accounts), the
// primary sub must always equal the username — otherwise password
// login would silently break after a rename, because login looks up
// (username, issuer) and compares the bcrypt hash on that row.
//
// For OIDC users (issuer != localIssuer) the sub is the IdP-assigned
// identifier and is left alone; only the Username changes.
//
// Validation, uniqueness checks, and the actual UPDATE happen in a
// single transaction so a failed sub update can't leave the row in a
// half-renamed state.
func RenameUser(db *gorm.DB, id, newUsername, localIssuer string) error {
	if err := ValidateIdentifier(newUsername); err != nil {
		return err
	}
	return db.Transaction(func(tx *gorm.DB) error {
		var user User
		if err := tx.First(&user, "id = ?", id).Error; err != nil {
			return err
		}
		if user.Username == newUsername {
			return nil
		}
		updates := map[string]interface{}{"username": newUsername}
		// Local-issuer accounts: keep the primary sub in lockstep so
		// password login (which looks up by (username, issuer) and
		// validates against the row's password_hash) keeps working.
		if localIssuer != "" && user.Issuer == localIssuer {
			updates["sub"] = newUsername
		}
		if err := tx.Model(&User{}).Where("id = ?", id).Updates(updates).Error; err != nil {
			return err
		}
		return nil
	})
}

// LookupOrBootstrapUser is the first-login (and every-subsequent-login)
// entry point for OIDC authentication.
//
// User-record contract (see comment on the User struct for the full model):
//   - (sub, issuer) is the *linkage* to the IdP identity. It is what we look
//     up against. It is never used for authorization decisions and is never
//     re-derived from the chosen username.
//   - Username is the *authorization handle*. On first sight of an identity we
//     bootstrap it from `usernameCandidates` (already resolved by the caller
//     from configured claims, in priority order); if every candidate collides
//     with an existing account we append a short random disambiguator to the
//     first candidate.
//   - DisplayName is a *human label*. It is refreshed on every login from
//     whatever the IdP currently reports — users who rename themselves at the
//     IdP get a fresh label without needing an admin's help. It does not
//     influence authorization in any way.
//
// On a return-visit (identity already linked) the username is left alone:
// once an account exists, only an administrator may rename it.
func LookupOrBootstrapUser(db *gorm.DB, sub, issuer, displayName string, usernameCandidates []string) (*User, error) {
	if sub == "" || issuer == "" {
		return nil, errors.New("sub and issuer are required")
	}
	if len(usernameCandidates) == 0 {
		return nil, errors.New("at least one username candidate is required")
	}

	// Existing identity → reuse the user, only refresh the human label.
	existing := &User{}
	err := db.Where("sub = ? AND issuer = ?", sub, issuer).First(existing).Error
	if err == nil {
		if displayName != "" && existing.DisplayName != displayName {
			if updErr := db.Model(existing).Update("display_name", displayName).Error; updErr != nil {
				// Log-and-continue would be nice, but this package has no
				// logger; return the error so the caller can decide.
				return nil, updErr
			}
			existing.DisplayName = displayName
		}
		return existing, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	// New identity → sanitize candidates through the identifier rules
	// first. Claims from third-party IdPs can contain anything; we don't
	// want to fail the login because of an unfortunate character (the
	// claim might be an email "alice/admin@..." which after stripping
	// the domain still has a slash). SanitizeIdentifier returns "" when
	// no salvageable form exists; we drop those.
	sanitized := make([]string, 0, len(usernameCandidates))
	for _, c := range usernameCandidates {
		if s := SanitizeIdentifier(c); s != "" {
			sanitized = append(sanitized, s)
		}
	}

	// Walk the sanitized candidates trying to claim a free username.
	for _, candidate := range sanitized {
		user, createErr := tryCreateUser(db, candidate, sub, issuer, displayName, CreatorSelf())
		if createErr == nil {
			return user, nil
		}
		if !isUniqueConstraintError(createErr) {
			return nil, createErr
		}
		// Username taken by some other account; try the next candidate.
	}

	// All sanitized candidates collided. Disambiguate the first one with
	// a short random suffix; we try a handful of times so a one-in-a-
	// million double-collision doesn't fail the whole login.
	base := ""
	if len(sanitized) > 0 {
		base = sanitized[0]
	}
	// Ensure base + "-XXXX" stays under the 64-char limit.
	const suffixHexLen = 4
	maxBase := 64 - 1 - suffixHexLen
	if len(base) > maxBase {
		base = base[:maxBase]
	}
	for i := 0; i < 8; i++ {
		suffix := make([]byte, 2)
		if _, rErr := rand.Read(suffix); rErr != nil {
			return nil, rErr
		}
		var candidate string
		if base != "" {
			candidate = base + "-" + hex.EncodeToString(suffix)
		} else {
			// No usable claim at all (e.g. all claims contained only
			// disallowed characters). Synthesise a name so the user
			// still gets an account; an admin can rename later.
			candidate = "user-" + hex.EncodeToString(suffix)
		}
		user, createErr := tryCreateUser(db, candidate, sub, issuer, displayName, CreatorSelf())
		if createErr == nil {
			return user, nil
		}
		if !isUniqueConstraintError(createErr) {
			return nil, createErr
		}
	}
	return nil, errors.New("could not allocate a unique username after exhausting candidates")
}

// tryCreateUser is a small wrapper around CreateUser that also stamps the
// initial display name. Kept private because CreateUser is the supported
// public surface for admin-driven user creation.
func tryCreateUser(db *gorm.DB, username, sub, issuer, displayName string, creator Creator) (*User, error) {
	slug, err := generateSlug()
	if err != nil {
		return nil, err
	}
	user := &User{
		ID:                  slug,
		Username:            username,
		Sub:                 sub,
		Issuer:              issuer,
		DisplayName:         displayName,
		CreatedBy:           creatorOrUnknown(creator.UserID),
		CreatorAuthMethod:   creator.AuthMethod,
		CreatorAuthMethodID: creator.AuthMethodID,
	}
	if err := db.Create(user).Error; err != nil {
		return nil, err
	}
	return user, nil
}

func isUniqueConstraintError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// CreateGroup persists a new group. The `creator` argument records who
// minted the group and how they were authenticated; CreatedBy is taken
// from creator.UserID (so it can be set even if the creator is not also
// the owner — though by default the creator becomes the owner). For
// API-driven creation pass the API token's audit info via captureAuthMethod.
func CreateGroup(db *gorm.DB, name, displayName, description string, creator Creator, groups []string) (*Group, error) {
	if err := ValidateIdentifier(name); err != nil {
		return nil, err
	}
	if err := ValidateDisplayName(displayName); err != nil {
		return nil, err
	}
	slug, err := generateSlug()
	if err != nil {
		return nil, err
	}

	// Disallow creating groups that start with the reserved personal-group prefix.
	if strings.HasPrefix(name, "user-") {
		return nil, ErrReservedGroupPrefix
	}

	createdBy := creatorOrUnknown(creator.UserID)
	// The creator becomes the initial owner unless they are an audit
	// sentinel rather than a real user; in that case there is no
	// natural owner to assign and the row is left ownerless until an
	// admin assigns one explicitly.
	owner := creator.UserID
	if owner == CreatorSelfEnrolled || owner == CreatorUnknown {
		owner = ""
	}

	group := &Group{
		ID:                  slug,
		Name:                name,
		DisplayName:         displayName,
		Description:         description,
		CreatedBy:           createdBy,
		CreatorAuthMethod:   creator.AuthMethod,
		CreatorAuthMethodID: creator.AuthMethodID,
		OwnerID:             owner,
	}

	if result := db.Create(group); result.Error != nil {
		return nil, result.Error
	}

	return group, nil
}

func GetGroupWithMembers(db *gorm.DB, groupId string) (*Group, error) {
	group := &Group{}
	if err := db.Preload("Members.User").First(group, "id = ?", groupId).Error; err != nil {
		return nil, err
	}
	return group, nil
}

func ListGroups(db *gorm.DB) ([]Group, error) {
	groups := []Group{}
	if err := db.Preload("Members.User").Find(&groups).Error; err != nil {
		return nil, err
	}
	return groups, nil
}

// isGroupOwnerOrAdmin checks whether the given userID is the group's owner,
// admin (when admin_type is 'user'), or a member of the admin group (when
// admin_type is 'group'). System admins bypass this check.
func isGroupOwnerOrAdmin(db *gorm.DB, group *Group, userID string, isSystemAdmin bool) bool {
	if isSystemAdmin {
		return true
	}
	// Owner can always manage. We deliberately do NOT fall back to
	// CreatedBy here: the design contract is explicit that simply
	// having created a group is not the same as owning it (a user
	// could be granted creator permission without being granted
	// ongoing access). Ownerless groups are backfilled to the admin
	// at startup — see BootstrapAdminAndBackfillOwners.
	if group.OwnerID == userID {
		return true
	}
	// Check admin
	if group.AdminID != "" {
		if group.AdminType == AdminTypeUser && group.AdminID == userID {
			return true
		}
		if group.AdminType == AdminTypeGroup {
			// Check if the user is a member of the admin group
			var count int64
			db.Model(&GroupMember{}).Where("group_id = ? AND user_id = ?", group.AdminID, userID).Count(&count)
			if count > 0 {
				return true
			}
		}
	}
	return false
}

// CanManageGroup is the exported wrapper around isGroupOwnerOrAdmin: returns
// true when the user can perform owner/admin-level actions (add/remove
// members, manage invite links, edit metadata).
func CanManageGroup(db *gorm.DB, group *Group, userID string, isSystemAdmin bool) bool {
	return isGroupOwnerOrAdmin(db, group, userID, isSystemAdmin)
}

// CanSeeGroup returns true when the user has any visibility into the group:
// system admin, owner, admin (user or via admin-group membership), member
// recorded in the DB, or member recorded in an external source (the
// caller's wlcg.groups claim, sourced from the OIDC IdP or the htpasswd
// bootstrap path). Used to gate read endpoints (GET /groups/:id, list
// members) so non-admin callers can see groups they belong to but not the
// rest of the federation.
//
// externalGroupNames is the slice of group *names* the caller's login
// cookie carried in. We match against group_name (not ID) because that's
// what every external source uses — see the contract on the Group
// struct: Name is the machine-readable handle and is what wlcg.groups
// carries.
func CanSeeGroup(db *gorm.DB, group *Group, userID string, isSystemAdmin bool, externalGroupNames []string) bool {
	if isGroupOwnerOrAdmin(db, group, userID, isSystemAdmin) {
		return true
	}
	var count int64
	db.Model(&GroupMember{}).Where("group_id = ? AND user_id = ?", group.ID, userID).Count(&count)
	if count > 0 {
		return true
	}
	if group.Name != "" {
		for _, n := range externalGroupNames {
			if n == group.Name {
				return true
			}
		}
	}
	return false
}

// ListGroupsVisibleToUser returns every group the user can see: groups they
// own, groups where they are AdminID (user or via admin-group membership),
// groups they are a row-member of, and groups whose *name* matches one of
// the externalGroupNames the caller asserted via their login cookie
// (wlcg.groups, populated from the OIDC IdP or the htpasswd bootstrap
// path). System admins should call ListGroups directly to see every group
// in the federation.
//
// External-source membership matters because the membership of a user in
// a group is not always recorded in the DB — an OIDC IdP can assert "this
// user belongs to group X" without us ever writing a group_members row.
// Filtering against the externalGroupNames slice (rather than just
// echoing it) drops any asserted name that doesn't correspond to a real
// group in the database, so we never pretend a non-existent group exists
// in API responses.
//
// The query unions five sources via SQL OR rather than running them
// separately; the helper is intentionally a single round-trip.
func ListGroupsVisibleToUser(db *gorm.DB, userID string, externalGroupNames []string) ([]Group, error) {
	groups := []Group{}
	// Build the list of group IDs the user can see, then fetch those groups.
	// Sources:
	//   1. groups.owner_id = userID
	//   2. groups.admin_id = userID AND admin_type = 'user'
	//   3. groups whose admin_id is a group the user is a member of
	//   4. groups the user is directly a row-member of
	//   5. groups whose name appears in the caller's cookie-asserted
	//      groups list (filtered to existing rows by the SQL itself)
	//
	// Note: there is no `created_by` clause. Per the design contract
	// having created a group does not by itself grant ongoing access
	// — ownerless groups are reassigned to the admin at startup
	// (BootstrapAdminAndBackfillOwners), so a real owner always exists.
	subq := db.Table("group_members").Select("group_id").Where("user_id = ?", userID)
	adminGroupIDs := db.Table("group_members").
		Select("groups.id").
		Joins("JOIN groups ON groups.admin_id = group_members.group_id AND groups.admin_type = ?", AdminTypeGroup).
		Where("group_members.user_id = ?", userID)
	// GORM rejects an empty IN-clause; substitute a value that cannot
	// match any real group name when the caller has no external groups.
	names := externalGroupNames
	if len(names) == 0 {
		names = []string{""}
	}
	// Preload Members.User so the list-page accordion can render
	// member rows without a follow-up GET /groups/:id per row.
	// ListGroups (the system-admin path) already does this; without
	// the matching preload here every group expanded from the
	// non-admin /groups response would show "No members yet" even
	// when the per-group page reveals real members.
	result := db.Model(&Group{}).
		Preload("Members.User").
		Where(
			"owner_id = ? OR (admin_type = ? AND admin_id = ?) OR id IN (?) OR id IN (?) OR name IN ?",
			userID, AdminTypeUser, userID, subq, adminGroupIDs, names,
		).Find(&groups)
	if result.Error != nil {
		return nil, result.Error
	}
	return groups, nil
}

// isGroupOwnerOnly checks whether the given userID is the group's owner.
// Only owners can change the owner or admin settings.
func isGroupOwnerOnly(group *Group, userID string, isSystemAdmin bool) bool {
	if isSystemAdmin {
		return true
	}
	if group.OwnerID == userID {
		return true
	}
	// No CreatedBy fallback — see comment on isGroupOwnerOrAdmin.
	return false
}

// UpdateGroup applies updates to a group's mutable fields. Authorization
// is split per the user/group design contract:
//
//   - Name (the machine-readable identifier used in policy strings) may
//     be changed ONLY by a system administrator. Owners and group-admins
//     cannot rename a group, because that would let them rewrite its
//     identity in any policy that references it.
//   - DisplayName and Description are owner-editable.
//
// `isAdmin` here is the *system admin* flag (the caller passed in from
// CheckAdmin); group-admin privileges flow through isGroupOwnerOrAdmin.
func UpdateGroup(db *gorm.DB, id string, name, displayName, description *string, requestorUserID string, isAdmin bool) error {
	updates := make(map[string]interface{})
	if name != nil {
		if !isAdmin {
			return ErrForbidden
		}
		if err := ValidateIdentifier(*name); err != nil {
			return err
		}
		if strings.HasPrefix(*name, "user-") {
			return ErrReservedGroupPrefix
		}
		updates["name"] = *name
	}
	if displayName != nil {
		if err := ValidateDisplayName(*displayName); err != nil {
			return err
		}
		updates["display_name"] = *displayName
	}
	if description != nil {
		updates["description"] = *description
	}

	if len(updates) == 0 {
		return nil
	}

	return db.Transaction(func(tx *gorm.DB) error {
		// Verify group exists and check authorization inside the transaction
		var group Group
		if err := tx.First(&group, "id = ?", id).Error; err != nil {
			return err
		}

		if !isGroupOwnerOrAdmin(tx, &group, requestorUserID, isAdmin) {
			return ErrForbidden
		}

		return tx.Model(&Group{}).Where("id = ?", id).Updates(updates).Error
	})
}

// UpdateGroupOwnership updates the owner and/or admin settings of a group.
// Only the group owner (or system admin) may change these settings.
func UpdateGroupOwnership(db *gorm.DB, id string, ownerID, adminID *string, adminType *AdminType, requestorUserID string, isSystemAdmin bool) error {
	return db.Transaction(func(tx *gorm.DB) error {
		var group Group
		if err := tx.First(&group, "id = ?", id).Error; err != nil {
			return err
		}

		if !isGroupOwnerOnly(&group, requestorUserID, isSystemAdmin) {
			return ErrForbidden
		}

		updates := make(map[string]interface{})
		if ownerID != nil {
			// Verify the new owner exists
			var user User
			if err := tx.First(&user, "id = ?", *ownerID).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return errors.New("new owner user does not exist")
				}
				return err
			}
			updates["owner_id"] = *ownerID
		}
		if adminID != nil {
			updates["admin_id"] = *adminID
		}
		if adminType != nil {
			updates["admin_type"] = *adminType
		}

		if len(updates) == 0 {
			return nil
		}

		return tx.Model(&Group{}).Where("id = ?", id).Updates(updates).Error
	})
}

func AddGroupMember(db *gorm.DB, groupId, userId, addedByUserId string, isAdmin bool) error {
	var group Group
	if err := db.First(&group, "id = ?", groupId).Error; err != nil {
		return err
	}

	if !isGroupOwnerOrAdmin(db, &group, addedByUserId, isAdmin) {
		return ErrForbidden
	}

	// Verify the user exists
	var user User
	if err := db.First(&user, "id = ?", userId).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.New("user does not exist")
		}
		return err
	}

	groupMember := &GroupMember{
		GroupID: groupId,
		UserID:  userId,
		AddedBy: addedByUserId,
	}
	// Idempotent: if the user is already a member of the group, treat
	// the call as a successful no-op rather than surfacing a UNIQUE
	// constraint failure. Two reasons:
	//
	//   - It matches caller intent ("ensure this user is a member").
	//     A "join myself" click that races against a stale UI, an
	//     admin re-adding a user who's already there, or a parallel
	//     redemption all just succeed.
	//
	//   - The SQLite driver in use (modernc.org/sqlite) doesn't
	//     translate UNIQUE-violations into the typed
	//     gorm.ErrDuplicatedKey, so the previous errors.Is() check
	//     never matched and the raw "constraint failed: UNIQUE
	//     constraint failed: group_members.group_id, ..." string
	//     bubbled up as a 500. The OnConflict clause sidesteps that
	//     entirely — the underlying SQL becomes INSERT ... ON
	//     CONFLICT DO NOTHING and there is no error to translate.
	if result := db.Clauses(clause.OnConflict{DoNothing: true}).Create(groupMember); result.Error != nil {
		return result.Error
	}
	return nil
}

func RemoveGroupMember(db *gorm.DB, groupId, userId, removedByUserId string, isAdmin bool) error {
	var group Group
	if err := db.First(&group, "id = ?", groupId).Error; err != nil {
		return err
	}

	// Allow removal if user is owner, admin, or system admin
	if !isGroupOwnerOrAdmin(db, &group, removedByUserId, isAdmin) {
		return ErrForbidden
	}

	if result := db.Where("group_id = ? AND user_id = ?", groupId, userId).Delete(&GroupMember{}); result.Error != nil {
		return result.Error
	}
	return nil
}

func GetMemberGroups(db *gorm.DB, userId string) ([]Group, error) {
	groups := []Group{}

	result := db.Model(&Group{}).
		Joins("JOIN group_members ON groups.id = group_members.group_id").
		Where("group_members.user_id = ?", userId).
		Find(&groups)
	if result.Error != nil {
		return nil, result.Error
	}
	return groups, nil
}

// UserCard is a small, non-sensitive summary of a user — just enough to
// render "Display Name (username)" without leaking the full User record.
// Used when the requester needs to see who owns / created / administers a
// group without being granted general user-listing privileges.
type UserCard struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
}

// GroupCard is the analogous summary for a group (e.g. when a group itself
// is the administrator of another group).
type GroupCard struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// GetUserCards resolves a list of user IDs to their public-safe UserCard
// summaries in a single round-trip. Unknown IDs are silently dropped from
// the returned map.
func GetUserCards(db *gorm.DB, ids []string) (map[string]UserCard, error) {
	out := map[string]UserCard{}
	if len(ids) == 0 {
		return out, nil
	}
	rows := []UserCard{}
	if err := db.Model(&User{}).
		Select("id, username, display_name").
		Where("id IN ?", ids).
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.ID] = r
	}
	return out, nil
}

// GetGroupCards resolves a list of group IDs to their summaries in a single
// round-trip.
func GetGroupCards(db *gorm.DB, ids []string) (map[string]GroupCard, error) {
	out := map[string]GroupCard{}
	if len(ids) == 0 {
		return out, nil
	}
	rows := []GroupCard{}
	if err := db.Model(&Group{}).
		Select("id, name").
		Where("id IN ?", ids).
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.ID] = r
	}
	return out, nil
}

// LeaveGroup removes the calling user's own membership from a group. This is
// distinct from RemoveGroupMember, which requires owner/admin privileges to
// remove other members. The group's owner cannot leave (they must transfer
// ownership first), since an ownerless group has no path back to making
// changes.
//
// Returns gorm.ErrRecordNotFound if the group does not exist or the user is
// not a member, and ErrForbidden if the user is the group's owner.
func LeaveGroup(db *gorm.DB, groupID, userID string) error {
	var group Group
	if err := db.First(&group, "id = ?", groupID).Error; err != nil {
		return err
	}
	if group.OwnerID == userID {
		return ErrForbidden
	}
	res := db.Where("group_id = ? AND user_id = ?", groupID, userID).Delete(&GroupMember{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func ListUsers(db *gorm.DB) ([]User, error) {
	users := []User{}
	if err := db.Find(&users).Error; err != nil {
		return nil, err
	}
	return users, nil
}

func GetAllCollections(db *gorm.DB) ([]Collection, error) {
	var collections []Collection
	if result := db.Find(&collections); result.Error != nil {
		return nil, result.Error
	}
	return collections, nil
}

// DeleteGroup deletes a group and cleans up any collection ACL entries that reference the
// group's name (ACLs store group names, not group slugs).
//
// Only the group owner or a system admin may delete the group.
func DeleteGroup(db *gorm.DB, groupID, requestorUserID string, isAdmin bool) error {
	return db.Transaction(func(tx *gorm.DB) error {
		// Fetch group inside transaction to avoid race conditions
		var group Group
		if err := tx.First(&group, "id = ?", groupID).Error; err != nil {
			return err
		}

		if !isGroupOwnerOnly(&group, requestorUserID, isAdmin) {
			return ErrForbidden
		}

		// Remove any invite links referencing the group.
		if err := tx.Where("group_id = ?", group.ID).Delete(&GroupInviteLink{}).Error; err != nil {
			return err
		}

		// Remove any ACL entries referencing the group name.
		if err := tx.Where("group_id = ?", group.Name).Delete(&CollectionACL{}).Error; err != nil {
			return err
		}

		// Delete group members explicitly (in addition to any FK cascade).
		if err := tx.Where("group_id = ?", group.ID).Delete(&GroupMember{}).Error; err != nil {
			return err
		}

		// Finally, delete the group itself.
		if err := tx.Delete(&group).Error; err != nil {
			return err
		}

		return nil
	})
}

// DeleteUser deletes a user and cleans up any collection ACL entries that reference the
// user's implicit personal group name ("user-"+username).
//
// If isAdmin is false, only the user themselves may delete their account.
func DeleteUser(db *gorm.DB, userID, requestorUserID string, isAdmin bool) error {
	return db.Transaction(func(tx *gorm.DB) error {
		// Fetch user inside transaction to avoid race conditions
		var user User
		if err := tx.First(&user, "id = ?", userID).Error; err != nil {
			return err
		}

		if !isAdmin && user.ID != requestorUserID {
			return ErrForbidden
		}

		personalGroup := "user-" + user.Username

		// Remove any ACL entries referencing the user's personal group name.
		if err := tx.Where("group_id = ?", personalGroup).Delete(&CollectionACL{}).Error; err != nil {
			return err
		}

		// Delete group memberships explicitly (in addition to any FK cascade).
		if err := tx.Where("user_id = ?", user.ID).Delete(&GroupMember{}).Error; err != nil {
			return err
		}

		// Finally, delete the user itself.
		if err := tx.Delete(&user).Error; err != nil {
			return err
		}

		return nil
	})
}

// --- Group Invite Link CRUD ---

// inviteTokenPrefixLen is the number of plaintext characters retained
// as the public short identifier for an invite link. 6 hex chars =
// 24 bits of entropy revealed — too little to brute-force the full
// token (which is bcrypt-hashed at rest) but plenty for humans to
// label and disambiguate live invites.
const inviteTokenPrefixLen = 6

// generateInviteToken creates a cryptographically random token for
// invite links. Returns (plaintext_token, public_prefix, error). The
// prefix is the first inviteTokenPrefixLen chars of the plaintext and
// is safe to log or display; the full plaintext is the credential
// and must only be returned to the link's recipient (once, at mint).
func generateInviteToken() (string, string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", "", err
	}
	plaintext := hex.EncodeToString(tokenBytes)
	prefix := plaintext[:inviteTokenPrefixLen]
	return plaintext, prefix, nil
}

// hashInviteToken returns a bcrypt hash of the plaintext token for secure storage.
func hashInviteToken(plaintext string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

// CreateGroupInviteLink creates a new invite link for a group. Only the group owner or admin
// (or a system admin) may create invite links.
// Returns (inviteLink, plaintextToken, error). The plaintext token is returned only once and not stored.
func CreateGroupInviteLink(db *gorm.DB, groupID, createdByUserID string, expiresAt time.Time, isSingleUse bool, isSystemAdmin bool, authMethod AuthMethod, authMethodID string) (*GroupInviteLink, string, error) {
	var group Group
	if err := db.First(&group, "id = ?", groupID).Error; err != nil {
		return nil, "", err
	}

	if !isGroupOwnerOrAdmin(db, &group, createdByUserID, isSystemAdmin) {
		return nil, "", ErrForbidden
	}

	link, plaintext, err := mintInviteLink(db, GroupInviteLink{
		Kind:         InviteKindGroup,
		GroupID:      groupID,
		CreatedBy:    createdByUserID,
		AuthMethod:   authMethod,
		AuthMethodID: authMethodID,
		ExpiresAt:    expiresAt,
		IsSingleUse:  isSingleUse,
	})
	if err != nil {
		return nil, "", err
	}
	return link, plaintext, nil
}

// CreateUserOnboardingInviteLink creates an invite link that onboards users
// without adding them to a group. Only system admins or user administrators can create these.
// Returns (inviteLink, plaintextToken, error).
func CreateUserOnboardingInviteLink(db *gorm.DB, createdByUserID string, expiresAt time.Time, isSingleUse bool, authMethod AuthMethod, authMethodID string) (*GroupInviteLink, string, error) {
	link, plaintext, err := mintInviteLink(db, GroupInviteLink{
		Kind:         InviteKindGroup, // historically a "group invite with no group"
		GroupID:      "",
		CreatedBy:    createdByUserID,
		AuthMethod:   authMethod,
		AuthMethodID: authMethodID,
		ExpiresAt:    expiresAt,
		IsSingleUse:  isSingleUse,
	})
	if err != nil {
		return nil, "", err
	}
	return link, plaintext, nil
}

// CreatePasswordInviteLink mints a single-use, expiring link that lets the
// holder set a password for `targetUserID` without ever showing it to the
// admin. The admin remains responsible for delivering the link out-of-band
// (email, hand it over in person, ...) — the system does not send it for
// them.
//
// Authorization is the caller's job; this function trusts that whoever
// calls it has already established the right to act on `targetUserID`
// (typically a system admin or user admin).
func CreatePasswordInviteLink(db *gorm.DB, targetUserID, createdByUserID string, expiresAt time.Time, authMethod AuthMethod, authMethodID string) (*GroupInviteLink, string, error) {
	if targetUserID == "" {
		return nil, "", errors.New("targetUserID is required")
	}
	// Confirm the target user actually exists; otherwise the redeem path
	// would silently fail later.
	if _, err := GetUserByID(db, targetUserID); err != nil {
		return nil, "", err
	}
	link, plaintext, err := mintInviteLink(db, GroupInviteLink{
		Kind:         InviteKindPassword,
		TargetUserID: targetUserID,
		CreatedBy:    createdByUserID,
		AuthMethod:   authMethod,
		AuthMethodID: authMethodID,
		ExpiresAt:    expiresAt,
		// Password invites are *always* single-use — once a password has
		// been set via the link, it must not be reusable to overwrite the
		// password again later.
		IsSingleUse: true,
	})
	if err != nil {
		return nil, "", err
	}
	return link, plaintext, nil
}

// mintInviteLink fills in the bookkeeping (id, token, hash, prefix) and
// writes the row. Callers populate the kind-specific fields (GroupID or
// TargetUserID), the audit fields (CreatedBy, AuthMethod...), and the
// lifecycle fields (ExpiresAt, IsSingleUse).
func mintInviteLink(db *gorm.DB, base GroupInviteLink) (*GroupInviteLink, string, error) {
	slug, err := generateSlug()
	if err != nil {
		return nil, "", err
	}
	plaintext, prefix, err := generateInviteToken()
	if err != nil {
		return nil, "", err
	}
	hashed, err := hashInviteToken(plaintext)
	if err != nil {
		return nil, "", err
	}
	base.ID = slug
	base.HashedToken = hashed
	base.TokenPrefix = prefix
	if base.Kind == "" {
		base.Kind = InviteKindGroup
	}
	if result := db.Create(&base); result.Error != nil {
		return nil, "", result.Error
	}
	return &base, plaintext, nil
}

// ListGroupInviteLinks returns all invite links for a given group.
func ListGroupInviteLinks(db *gorm.DB, groupID string) ([]GroupInviteLink, error) {
	var links []GroupInviteLink
	if err := db.Where("group_id = ?", groupID).Find(&links).Error; err != nil {
		return nil, err
	}
	return links, nil
}

// GetGroupInviteLinkByToken looks up an invite link by scanning all non-revoked,
// non-expired links and comparing the bcrypt hash. Returns nil if not found.
func GetGroupInviteLinkByToken(db *gorm.DB, plaintext string) (*GroupInviteLink, error) {
	var links []GroupInviteLink
	if err := db.Where("revoked = 0 AND expires_at > ?", time.Now()).Find(&links).Error; err != nil {
		return nil, err
	}
	for i := range links {
		if err := bcrypt.CompareHashAndPassword([]byte(links[i].HashedToken), []byte(plaintext)); err == nil {
			return &links[i], nil
		}
	}
	return nil, gorm.ErrRecordNotFound
}

// RedeemGroupInviteLink redeems an invite link, adding the user to the group.
// It validates the link is not expired, not revoked, and (if single-use) not already redeemed.
// If the user does not exist and sub+issuer are provided, the user is auto-created.
// If username is empty, a username is derived from the sub.
// RedeemGroupInviteLink consumes a plaintext invite token, resolves or
// auto-creates the user from the supplied identity, and adds them to the
// link's group (if any). Returns the joined group's ID on success — empty
// string for user-onboarding invites that don't reference a group.
// RedeemGroupInviteLink returns (joinedGroupID, resolvedUserID, error).
// joinedGroupID is empty for user-onboarding invites that have no group;
// resolvedUserID is the user that ended up joined (auto-created or
// pre-existing). Useful so callers can update audit trails and redirect
// the caller to the right place after redemption.
func RedeemGroupInviteLink(db *gorm.DB, plaintext string, userID string, sub string, issuer string, username string) (string, string, error) {
	var groupID, finalUserID string
	err := db.Transaction(func(tx *gorm.DB) error {
		// Scan non-revoked, non-expired links and bcrypt-compare
		var links []GroupInviteLink
		if err := tx.Where("revoked = 0 AND expires_at > ?", time.Now()).Find(&links).Error; err != nil {
			return err
		}
		var link *GroupInviteLink
		for i := range links {
			if err := bcrypt.CompareHashAndPassword([]byte(links[i].HashedToken), []byte(plaintext)); err == nil {
				link = &links[i]
				break
			}
		}
		if link == nil {
			return gorm.ErrRecordNotFound
		}
		// This entry point is the *group/onboarding* redeem path. Password
		// invites must go through RedeemPasswordInviteLink (no auth, takes
		// a password); falling through to here would silently no-op for
		// them and look like a successful redemption.
		if link.Kind == InviteKindPassword {
			return errors.New("this is a password-set invite; redeem it via the password endpoint")
		}

		if link.Revoked {
			return errors.New("invite link has been revoked")
		}

		if time.Now().After(link.ExpiresAt) {
			return errors.New("invite link has expired")
		}

		if link.IsSingleUse && link.RedeemedBy != "" {
			return errors.New("invite link has already been redeemed")
		}

		// Resolve or auto-create the user
		var resolvedUserID string
		if userID != "" {
			// Try to find existing user by ID
			var user User
			if err := tx.First(&user, "id = ?", userID).Error; err != nil {
				if !errors.Is(err, gorm.ErrRecordNotFound) {
					return err
				}
				// User ID not found; fall through to auto-create
			} else {
				resolvedUserID = user.ID
			}
		}

		if resolvedUserID == "" && sub != "" && issuer != "" {
			// Try to find by identity (primary or secondary)
			existingUser, err := GetUserByIdentity(tx, sub, issuer)
			if err == nil {
				resolvedUserID = existingUser.ID
			} else if errors.Is(err, gorm.ErrRecordNotFound) {
				// Auto-create the user. The link's CreatedBy is the
				// admin who minted the invite, so they're effectively
				// the creator of the resulting account; we propagate
				// the link's auth-method bookkeeping the same way an
				// admin-driven CreateUser would.
				if username == "" {
					username = sub
				}
				newUser, createErr := CreateUser(tx, username, sub, issuer, Creator{
					UserID:       link.CreatedBy,
					AuthMethod:   link.AuthMethod,
					AuthMethodID: link.AuthMethodID,
				})
				if createErr != nil {
					return fmt.Errorf("failed to auto-create user: %w", createErr)
				}
				resolvedUserID = newUser.ID
			} else {
				return err
			}
		}

		if resolvedUserID == "" {
			return errors.New("user does not exist and cannot be auto-created (missing identity)")
		}

		// If the link has a group, add the user to that group
		if link.GroupID != "" {
			groupMember := &GroupMember{
				GroupID: link.GroupID,
				UserID:  resolvedUserID,
				AddedBy: link.CreatedBy,
			}
			if result := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(groupMember); result.Error != nil {
				return result.Error
			}
		}
		// If GroupID is empty, this is a user-onboarding invite; no group addition needed.

		// Mark the link as redeemed. For single-use links the UPDATE is
		// conditional on redeemed_by still being empty: if a concurrent
		// redemption beat us to it, our UPDATE matches zero rows and we
		// abort the whole transaction so the group-membership write is
		// rolled back too. The in-memory check above is a fast path; this
		// is the actual race-safe guard.
		now := time.Now()
		updates := map[string]interface{}{
			"redeemed_by": resolvedUserID,
			"redeemed_at": now,
		}
		if link.IsSingleUse {
			res := tx.Model(&GroupInviteLink{}).
				Where("id = ? AND redeemed_by = ''", link.ID).
				Updates(updates)
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected == 0 {
				return errors.New("invite link was concurrently redeemed")
			}
		} else {
			if err := tx.Model(&link).Updates(updates).Error; err != nil {
				return err
			}
		}

		// Capture so the caller can deep-link to the joined group; empty
		// for user-onboarding invites. finalUserID is the user that was
		// either auto-created or matched by ID/identity.
		groupID = link.GroupID
		finalUserID = resolvedUserID
		return nil
	})
	if err != nil {
		return "", "", err
	}
	return groupID, finalUserID, nil
}

// RedeemPasswordInviteLink consumes a password-kind invite token and sets
// the bcrypt hash for the link's TargetUserID. The caller is *not*
// authenticated — possession of the token IS the credential, by design
// (this is "click the link to set your password"). The link is single-use
// by construction (see CreatePasswordInviteLink); a successful redemption
// marks it as redeemed so the same link cannot rotate the password later.
//
// Returns the affected user's ID on success — useful so the caller can
// e.g. immediately log the user in via setLoginCookie.
func RedeemPasswordInviteLink(db *gorm.DB, plaintext, newPassword string) (string, error) {
	if newPassword == "" {
		return "", errors.New("password is required")
	}
	hashed, hashErr := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if hashErr != nil {
		return "", hashErr
	}

	var userID string
	err := db.Transaction(func(tx *gorm.DB) error {
		// Same scan-and-bcrypt-compare loop the group redeem uses; we
		// can't index on the hash (bcrypt is salted) so a linear scan
		// over the small set of live links is unavoidable.
		var links []GroupInviteLink
		if err := tx.Where("revoked = 0 AND expires_at > ?", time.Now()).Find(&links).Error; err != nil {
			return err
		}
		var link *GroupInviteLink
		for i := range links {
			if err := bcrypt.CompareHashAndPassword([]byte(links[i].HashedToken), []byte(plaintext)); err == nil {
				link = &links[i]
				break
			}
		}
		if link == nil {
			return gorm.ErrRecordNotFound
		}
		if link.Kind != InviteKindPassword {
			return errors.New("this invite link is not a password-set invite")
		}
		if link.IsSingleUse && link.RedeemedBy != "" {
			return errors.New("invite link has already been redeemed")
		}
		if link.TargetUserID == "" {
			return errors.New("password invite link is missing a target user (data corruption)")
		}

		// Mark the link redeemed FIRST, conditionally on it still being
		// unredeemed. Password invites are always single-use; this UPDATE
		// is the verify-and-claim that has to win exactly once per token.
		// If a concurrent redemption beat us, RowsAffected is 0, we
		// return the error and the transaction rolls back without ever
		// writing the hash. Doing the link-claim before the hash write
		// gives us "set the password atomically with claiming the
		// token", with no chance of a hash being written for a
		// re-redeemed link.
		now := time.Now()
		res := tx.Model(&GroupInviteLink{}).
			Where("id = ? AND redeemed_by = ''", link.ID).
			Updates(map[string]interface{}{
				"redeemed_by": link.TargetUserID,
				"redeemed_at": now,
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return errors.New("invite link was concurrently redeemed")
		}

		// Now apply the password. The hash write goes through the
		// credential helper so the User struct itself never touches the
		// column — see database/credentials.go.
		if err := applyHashInTx(tx, link.TargetUserID, string(hashed)); err != nil {
			return err
		}
		userID = link.TargetUserID
		return nil
	})
	if err != nil {
		return "", err
	}
	return userID, nil
}

// LookupInviteLinkByToken returns the invite-link metadata for an opaque
// token, after verifying it is live (not revoked, not expired, and — for
// single-use links — not already redeemed). Used to back the
// pre-redemption "what kind of invite is this?" probe so the UI can
// render the right form (password entry vs. group-join confirmation).
//
// The HashedToken is intentionally elided from the returned record, but
// otherwise this is the full row, so callers should treat it as
// non-public information (the token-bearer at least already had to know
// the token, but cards-with-token aren't free).
func LookupInviteLinkByToken(db *gorm.DB, plaintext string) (*GroupInviteLink, error) {
	var links []GroupInviteLink
	if err := db.Where("revoked = 0 AND expires_at > ?", time.Now()).Find(&links).Error; err != nil {
		return nil, err
	}
	for i := range links {
		if err := bcrypt.CompareHashAndPassword([]byte(links[i].HashedToken), []byte(plaintext)); err == nil {
			if links[i].IsSingleUse && links[i].RedeemedBy != "" {
				return nil, gorm.ErrRecordNotFound
			}
			out := links[i]
			out.HashedToken = ""
			return &out, nil
		}
	}
	return nil, gorm.ErrRecordNotFound
}

// ListPasswordInvitesForUser returns all password-set invites that target
// the given user (used for an admin UI to see, e.g., "this user has 2
// outstanding setup links and 1 has already been used"). Includes
// already-redeemed and revoked links so the audit trail is visible.
func ListPasswordInvitesForUser(db *gorm.DB, userID string) ([]GroupInviteLink, error) {
	var links []GroupInviteLink
	if err := db.Where("kind = ? AND target_user_id = ?", InviteKindPassword, userID).
		Order("created_at DESC").Find(&links).Error; err != nil {
		return nil, err
	}
	return links, nil
}

// RevokeGroupInviteLink revokes an invite link. Only the group owner or admin
// (or a system admin) may revoke invite links.
func RevokeGroupInviteLink(db *gorm.DB, linkID, requestorUserID string, isSystemAdmin bool) error {
	return db.Transaction(func(tx *gorm.DB) error {
		var link GroupInviteLink
		if err := tx.First(&link, "id = ?", linkID).Error; err != nil {
			return err
		}

		// Authorization differs by kind. Group invites need an
		// owner/admin of the *target group*; password invites have no
		// group context so we let the link's creator (or any system
		// admin) revoke them.
		switch link.Kind {
		case InviteKindPassword:
			if !isSystemAdmin && link.CreatedBy != requestorUserID {
				return ErrForbidden
			}
		default: // InviteKindGroup (and the historical empty-group user-onboarding invite)
			if link.GroupID == "" {
				if !isSystemAdmin && link.CreatedBy != requestorUserID {
					return ErrForbidden
				}
			} else {
				var group Group
				if err := tx.First(&group, "id = ?", link.GroupID).Error; err != nil {
					return err
				}
				if !isGroupOwnerOrAdmin(tx, &group, requestorUserID, isSystemAdmin) {
					return ErrForbidden
				}
			}
		}

		return tx.Model(&link).Update("revoked", true).Error
	})
}

// --- User Status and AUP ---

// UpdateUserStatus updates the status (active/inactive) of a user.
func UpdateUserStatus(db *gorm.DB, userID string, status UserStatus) error {
	return db.Model(&User{}).Where("id = ?", userID).Update("status", status).Error
}

// UpdateUserLastLogin updates the last login timestamp of a user.
func UpdateUserLastLogin(db *gorm.DB, userID string) error {
	return db.Model(&User{}).Where("id = ?", userID).Update("last_login_at", time.Now()).Error
}

// UpdateUserDisplayName updates the display name of a user.
func UpdateUserDisplayName(db *gorm.DB, userID string, displayName string) error {
	return db.Model(&User{}).Where("id = ?", userID).Update("display_name", displayName).Error
}

// RecordAUPAgreement records that a user agreed to a specific version of the AUP.
func RecordAUPAgreement(db *gorm.DB, userID string, version string) error {
	now := time.Now()
	return db.Model(&User{}).Where("id = ?", userID).Updates(map[string]interface{}{
		"aup_version":   version,
		"aup_agreed_at": now,
	}).Error
}

// ClearAUPAgreement wipes a user's recorded AUP acceptance so the
// next /whoami fetch (and therefore the AuthenticatedContent gate)
// flags them as needing to re-accept. Useful when an admin wants to
// force a single user back through the workflow without rotating the
// active AUP version for everyone.
//
// We blank both columns rather than just bumping aup_version because
// aup_agreed_at is part of the audit trail; preserving a stale
// timestamp here would suggest the user signed when they did not.
// Returns gorm.ErrRecordNotFound when the user ID doesn't resolve.
func ClearAUPAgreement(db *gorm.DB, userID string) error {
	res := db.Model(&User{}).Where("id = ?", userID).Updates(map[string]interface{}{
		"aup_version":   "",
		"aup_agreed_at": nil,
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// --- User Identity CRUD ---

// CreateUserIdentity associates a new identity (sub + issuer) with an existing user.
func CreateUserIdentity(db *gorm.DB, userID, sub, issuer string) (*UserIdentity, error) {
	if userID == "" || sub == "" || issuer == "" {
		return nil, errors.New("userID, sub, and issuer are required")
	}

	// Cross-table check: per the design contract, a user has at most
	// one identity per issuer — counting BOTH the secondary identities
	// in this table AND the primary identity carried on the User row.
	// SQLite has no cross-table constraint mechanism, so we enforce
	// it here. (The within-table check is redundant with the unique
	// index on (user_id, issuer); it's still useful for a clearer
	// error message.)
	var primary User
	if err := db.First(&primary, "id = ?", userID).Error; err != nil {
		return nil, err
	}
	if primary.Issuer == issuer {
		return nil, errors.New("user already has an identity at this issuer (the primary one)")
	}

	slug, err := generateSlug()
	if err != nil {
		return nil, err
	}

	identity := &UserIdentity{
		ID:     slug,
		UserID: userID,
		Sub:    sub,
		Issuer: issuer,
	}

	if result := db.Create(identity); result.Error != nil {
		if strings.Contains(result.Error.Error(), "UNIQUE constraint failed") {
			return nil, errors.New("identity (sub, issuer) is already linked, or the user already has an identity at this issuer")
		}
		return nil, result.Error
	}

	return identity, nil
}

// ListUserIdentities returns all identities for a given user.
func ListUserIdentities(db *gorm.DB, userID string) ([]UserIdentity, error) {
	var identities []UserIdentity
	if err := db.Where("user_id = ?", userID).Find(&identities).Error; err != nil {
		return nil, err
	}
	return identities, nil
}

// DeleteUserIdentity removes a specific *secondary* identity row.
// Returns gorm.ErrRecordNotFound if no row matches (identity ID
// unknown, or it belongs to a different user) — same observable
// behavior either way, so handlers don't need to distinguish "wrong
// user" from "doesn't exist" and accidentally leak existence.
//
// This function only operates on the user_identities table; the
// primary identity carried on the User row is intentionally not
// removable here. See the user/group design contract.
func DeleteUserIdentity(db *gorm.DB, identityID, userID string) error {
	result := db.Where("id = ? AND user_id = ?", identityID, userID).Delete(&UserIdentity{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// GetUserByIdentity looks up a user by an identity (sub + issuer), checking both
// the primary user table and the user_identities table.
func GetUserByIdentity(db *gorm.DB, sub, issuer string) (*User, error) {
	// First check the primary user table
	user := &User{}
	err := db.Where("sub = ? AND issuer = ?", sub, issuer).First(user).Error
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	// Check the user_identities table
	var identity UserIdentity
	if err := db.Where("sub = ? AND issuer = ?", sub, issuer).First(&identity).Error; err != nil {
		return nil, err
	}

	// Found via identity, look up the user
	if err := db.First(user, "id = ?", identity.UserID).Error; err != nil {
		return nil, err
	}
	return user, nil
}
