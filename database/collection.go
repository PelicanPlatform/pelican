package database

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
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
	// ErrUnknownACLSubject is returned by ResolveACLSubject (and so by
	// GrantCollectionAcl / RevokeCollectionAcl) when the requested ACL
	// target names no group and no user on this server. ACL rows are
	// keyed on immutable IDs, so there is nothing to store for an
	// unknown name; the pre-ID code path that silently persisted the
	// raw string is what let a later claimant of that name inherit the
	// grant (issue #3752).
	ErrUnknownACLSubject = errors.New("unknown collection ACL subject")
	// ErrMembershipNotLocal is returned when a caller tries to remove a
	// group membership that came from a provider's assertion rather than
	// from the group-management API. Deleting the row would not remove
	// the person from the group — the provider still asserts it, and the
	// next login mirrors it straight back — so the operation is refused
	// rather than quietly appearing to work.
	ErrMembershipNotLocal = errors.New("membership is asserted by a group source and cannot be removed here")
	// ErrGroupNameConflict is returned when a Pelican-created group
	// would take — or an admin would rename a group to — a name that an
	// identity provider is already known to assert. See
	// EnsureAssertedGroups.
	ErrGroupNameConflict = errors.New("group name is already claimed by a group source")
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

// AllAuthenticatedUsersACLGroup is the wire-format sentinel that a
// caller may pass (and that the API echoes back) to mean "every
// authenticated caller, regardless of group membership". In the
// database this is stored as a CollectionACL row whose SubjectType is
// ACLSubjectAuthenticated and whose SubjectID is empty — the sentinel
// string never reaches a column. It begins with `@`, which
// `ValidateIdentifier` rejects (identifiers must start with an
// alphanumeric), so it can never collide with a real Group.Name.
const AllAuthenticatedUsersACLGroup = "@authenticated"

// PersonalACLGroupPrefix is the wire-format prefix that names a single
// user as an ACL target: `user-alice` means "the user currently named
// alice". Like AllAuthenticatedUsersACLGroup this is a *presentation*
// form only — the stored row carries SubjectType ACLSubjectUser and
// the user's immutable User.ID, so renaming or deleting the account
// does not leave a grant behind for whoever claims the name next.
// CreateGroup reserves the prefix so no real group can shadow it.
const PersonalACLGroupPrefix = "user-"

// IsACLGroupVirtual reports whether `name` is a known virtual ACL
// target — currently only the all-authenticated-users sentinel.
// Frontends and CLI surfaces consult this to render a friendly label
// instead of the bare `@authenticated` string, and the ACL grant
// resolver uses it to skip the "real group must exist" lookup.
func IsACLGroupVirtual(name string) bool {
	return name == AllAuthenticatedUsersACLGroup
}

// ACLSubjectType discriminates what kind of principal a CollectionACL
// row grants its role to. It exists so every ACL row can be keyed on
// an immutable ID instead of a mutable name: before this, a single
// `group_id` TEXT column held a group name, a synthesized
// `user-<username>`, or the `@authenticated` sentinel, and a rename or
// a soft-delete left the grant dangling under a name anybody could
// reclaim (issue #3752).
//
//   - ACLSubjectGroup — SubjectID is a Group.ID.
//   - ACLSubjectUser — SubjectID is a User.ID. This replaces the
//     `user-<username>` personal-group synthesis.
//   - ACLSubjectAuthenticated — SubjectID is empty; the row matches
//     any caller with an identity. Modelled as its own type rather
//     than a magic ID value so no ID has to be reserved.
type ACLSubjectType string

const (
	ACLSubjectGroup         ACLSubjectType = "group"
	ACLSubjectUser          ACLSubjectType = "user"
	ACLSubjectAuthenticated ACLSubjectType = "authenticated"
)

var (
	ScopeToRole map[token_scopes.TokenScope][]AclRole = map[token_scopes.TokenScope][]AclRole{
		token_scopes.Collection_Read:   {AclRoleRead, AclRoleWrite, AclRoleOwner},
		token_scopes.Collection_Modify: {AclRoleWrite, AclRoleOwner},
		token_scopes.Collection_Delete: {AclRoleOwner},
	}
)

// FilterAuthTemplateEligibleGroups removes from `names` any group
// whose DB row has auth_template_eligible == false. Names that have
// no DB row at all (purely OIDC-asserted, no Pelican-managed Group)
// pass through unchanged — eligibility is a flag on Pelican-managed
// rows; we don't deny names this server doesn't even know about.
//
// Used by every authz consumer that treats group names as bearer
// authority: the issuer's `Issuer.AuthorizationTemplates` matcher
// (oa4mp) and the `Server.*AdminGroups` config matcher
// (web_ui.EffectiveScopesForIdentity). Collection-ACL evaluation
// does NOT call this — collection ACLs are operator-set per row,
// and the unique-name constraint already prevents a self-created
// group from impersonating an admin-named one.
//
// Empty input → empty output. DB errors fall back to returning the
// input unchanged: a transient DB hiccup must not silently strip a
// user's group memberships and turn them into an unprivileged
// caller. The downside is a brief window where a freshly-flagged
// ineligible group still matches templates — acceptable.
func FilterAuthTemplateEligibleGroups(db *gorm.DB, names []string) []string {
	if db == nil || len(names) == 0 {
		return names
	}
	// Names that exist in the DB AND are flagged ineligible. Anything
	// else (eligible, or not in the DB at all) is kept.
	type row struct{ Name string }
	var rows []row
	if err := db.Table("groups").
		Select("name").
		Where("name IN ? AND auth_template_eligible = 0 AND deleted_at IS NULL", names).
		Scan(&rows).Error; err != nil {
		return names
	}
	if len(rows) == 0 {
		return names
	}
	excluded := make(map[string]struct{}, len(rows))
	for _, r := range rows {
		excluded[r.Name] = struct{}{}
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if _, drop := excluded[n]; drop {
			continue
		}
		out = append(out, n)
	}
	return out
}

// CallerACLSubjects is the ID-keyed identity of one caller, as used by
// every collection authorization decision. It is the replacement for
// the old "list of group names" the ACL evaluator used to match on:
// names are mutable and reusable, IDs are neither.
//
//   - UserID is the caller's live User.ID, or "" when the caller has
//     no user row (a bearer token minted for a federation identity
//     this server has never seen).
//   - GroupIDs are Group.IDs, gathered from BOTH the `group_members`
//     table (membership recorded in this server) and the caller's
//     provider-asserted group names resolved through `groups.name`.
//   - Authenticated is true whenever the caller presented any
//     identity at all; it is what makes an `@authenticated` ACL row
//     match. An anonymous request leaves it false.
type CallerACLSubjects struct {
	UserID        string
	GroupIDs      []string
	Authenticated bool
}

// Matches reports whether the supplied ACL row grants its role to this
// caller. Expiry is NOT considered here — callers filter expired rows
// themselves, because several of them want to keep scanning for a
// second, still-valid grant.
func (s CallerACLSubjects) Matches(acl CollectionACL) bool {
	switch acl.SubjectType {
	case ACLSubjectAuthenticated:
		return s.Authenticated
	case ACLSubjectUser:
		return s.UserID != "" && acl.SubjectID == s.UserID
	case ACLSubjectGroup:
		return acl.SubjectID != "" && slices.Contains(s.GroupIDs, acl.SubjectID)
	}
	return false
}

// ACLWhere returns a SQL fragment (plus its arguments) selecting the
// `collection_acls` rows that match this caller, for use with an
// already-joined `collection_acls` table. Returns ("", nil) when the
// caller can match nothing at all, so callers can skip the query
// entirely rather than emitting a `WHERE false`.
func (s CallerACLSubjects) ACLWhere() (string, []any) {
	clauses := []string{}
	args := []any{}
	if s.Authenticated {
		clauses = append(clauses, "collection_acls.subject_type = ?")
		args = append(args, ACLSubjectAuthenticated)
	}
	if s.UserID != "" {
		clauses = append(clauses, "(collection_acls.subject_type = ? AND collection_acls.subject_id = ?)")
		args = append(args, ACLSubjectUser, s.UserID)
	}
	if len(s.GroupIDs) > 0 {
		clauses = append(clauses, "(collection_acls.subject_type = ? AND collection_acls.subject_id IN ?)")
		args = append(args, ACLSubjectGroup, s.GroupIDs)
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return "(" + strings.Join(clauses, " OR ") + ")", args
}

// ResolveCallerACLSubjects turns the three identity fragments the HTTP
// layer carries — username, User.ID, and the provider-asserted group
// NAMES from the caller's cookie or token — into the ID-keyed subject
// set the ACL evaluator matches on.
//
// Resolving a *caller's* name to an ID is safe in a way that storing a
// name in an ACL row is not: it answers "who is this name right now",
// and the answer is a single live row. The vulnerability closed by the
// ID-keyed model was the reverse direction — a stored grant naming a
// principal that had since been renamed or deleted.
//
// Group IDs come from two sources, unioned:
//
//   - `group_members` joined on the caller's User.ID — both the
//     memberships an administrator created and the ones mirrored from a
//     provider's assertion, the latter only while still fresh. This is
//     what makes the management UI work for callers whose cookie carries
//     no group claim at all (htpasswd login, or OIDC with
//     `Issuer.GroupSource: none`), and what lets a decision be made
//     about a user who is not currently making a request.
//   - The caller-supplied names, resolved through `groups.name`. With
//     group auto-creation on (the default, see EnsureAssertedGroups)
//     every name a provider asserts has a record, so this resolves; a
//     name with no record simply contributes nothing, exactly as an
//     unmatched name did before.
//
// `db` may be nil for in-memory unit tests, in which case only the
// caller's own User.ID and the authenticated flag are populated. Query
// errors are tolerated the same way: the caller falls back to a
// narrower view rather than failing the whole request.
func ResolveCallerACLSubjects(db *gorm.DB, username, userID string, groupNames []string) CallerACLSubjects {
	out := CallerACLSubjects{
		UserID:        userID,
		Authenticated: username != "" || userID != "",
	}
	if db == nil {
		return out
	}
	// A caller identified only by username (legacy call sites, and
	// bearer tokens that carry no user_id claim) still needs their
	// User.ID for the personal-grant match.
	if out.UserID == "" && username != "" {
		var u User
		if err := db.Select("id").Where("username = ?", username).First(&u).Error; err == nil {
			out.UserID = u.ID
		}
	}
	seen := map[string]struct{}{}
	add := func(id string) {
		if id == "" {
			return
		}
		if _, ok := seen[id]; ok {
			return
		}
		seen[id] = struct{}{}
		out.GroupIDs = append(out.GroupIDs, id)
	}
	if out.UserID != "" {
		// Pelican-created memberships, plus mirrored ones the provider
		// has asserted recently enough to still grant. A stale mirrored
		// row is deliberately excluded here: this path decides what to
		// hand out. See grantingMembershipsFor.
		if ids, err := grantingMembershipsFor(db, out.UserID); err == nil {
			for _, id := range ids {
				add(id)
			}
		}
	}
	if len(groupNames) > 0 {
		var rows []struct{ ID string }
		// deleted_at is spelled out because this is a raw table query:
		// GORM's soft-delete scope only applies to model-based queries,
		// and a deleted group must not keep conferring ACL matches.
		if err := db.Table("groups").
			Select("id").
			Where("name IN ? AND deleted_at IS NULL", groupNames).
			Scan(&rows).Error; err == nil {
			for _, r := range rows {
				add(r.ID)
			}
		}
	}
	return out
}

// ACLSubjectRef is a NAME-space reference to an ACL target: a group
// name, `user-<username>`, or the `@authenticated` sentinel. It is what
// a human writes and what a provider asserts.
//
// It is a distinct type from a plain string on purpose. The name space
// and the ID space are different things that happen to share a Go
// representation, and a function that accepts "either" has to guess
// which one it was handed — which is not a guess that can be made
// safely. Group creation is open to any authenticated user, so if a
// resolver ever consults names and IDs together, creating a group NAMED
// after another principal's ID is enough to intercept every grant
// addressed to that ID. Making the two spaces separate types means the
// resolver never has to ask, and a caller that has an ID cannot reach a
// name lookup by accident: converting is an explicit, greppable act.
type ACLSubjectRef string

// ACLSubject is the stored, ID-space identity of an ACL target: what
// actually lands in `collection_acls`. Kind and ID together, never a
// bare string, because an ID alone does not say which table it is in.
type ACLSubject struct {
	Type ACLSubjectType
	ID   string
}

// ResolveCallerACLSubjectsToleratingStale is ResolveCallerACLSubjects
// with the mirrored-membership freshness cutoff lifted.
//
// It exists for exactly one caller: the share-token clamp, which asks
// what a SHARE'S OWNER can currently do on the parent collection, at
// mint time, with no session for that owner. Gating that on freshness
// produces a false denial rather than a safe one — an owner who has not
// signed in for longer than the TTL silently has every share they
// created mint tokens with no storage scopes, while the provider still
// lists them as a member the whole time, and nothing logs it. Weighed
// against a bounded staleness window on a ceiling that only ever
// NARROWS what a recipient already has an ACL for, the denial is worse.
//
// Do not reach for this anywhere else. Every other granting path uses
// the gated form; this one is a deliberate, argued exception.
func ResolveCallerACLSubjectsToleratingStale(db *gorm.DB, username, userID string) CallerACLSubjects {
	out := ResolveCallerACLSubjects(db, username, userID, nil)
	if db == nil || out.UserID == "" {
		return out
	}
	var rows []struct{ GroupID string }
	if err := db.Table("group_members").
		Select("group_id").
		Joins("JOIN groups ON groups.id = group_members.group_id AND groups.deleted_at IS NULL").
		Where("group_members.user_id = ?", out.UserID).
		Scan(&rows).Error; err != nil {
		return out
	}
	for _, r := range rows {
		if r.GroupID != "" && !slices.Contains(out.GroupIDs, r.GroupID) {
			out.GroupIDs = append(out.GroupIDs, r.GroupID)
		}
	}
	return out
}

// ResolveACLSubjectRef turns a name-space reference into the stored
// subject.
//
// Name space ONLY. A group ID handed to this function does not resolve,
// because no group is *named* that — which is the correct outcome, not a
// limitation: callers holding an ID use LookupACLSubject and say so.
//
// It NEVER falls back to "trust the caller and store the string" the way
// the pre-ID model did: an unresolvable reference is an error, because
// storing it would recreate the dangling-name grant of issue #3752.
// Operators who want to pre-grant access to a provider-asserted group
// that nobody has logged in with yet create the group first
// (`POST /api/v1.0/groups`), which is also where the
// auth-template-eligibility decision belongs.
func ResolveACLSubjectRef(db *gorm.DB, ref ACLSubjectRef) (ACLSubject, error) {
	target := strings.TrimSpace(string(ref))
	if target == "" {
		return ACLSubject{}, errors.New("ACL subject is required")
	}
	if IsACLGroupVirtual(target) {
		return ACLSubject{Type: ACLSubjectAuthenticated}, nil
	}
	if db == nil {
		return ACLSubject{}, errors.New("database is required to resolve an ACL subject")
	}
	if name, ok := strings.CutPrefix(target, PersonalACLGroupPrefix); ok {
		var u User
		if err := db.Select("id").Where("username = ?", name).First(&u).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ACLSubject{}, fmt.Errorf("%w: no such user %q", ErrUnknownACLSubject, name)
			}
			return ACLSubject{}, err
		}
		return ACLSubject{Type: ACLSubjectUser, ID: u.ID}, nil
	}
	var grp Group
	if err := db.Select("id").Where("name = ?", target).First(&grp).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ACLSubject{}, fmt.Errorf(
				"%w: no group is named %q (name a user as %s<username>, or address either by subjectType/subjectId)",
				ErrUnknownACLSubject, target, PersonalACLGroupPrefix)
		}
		return ACLSubject{}, err
	}
	return ACLSubject{Type: ACLSubjectGroup, ID: grp.ID}, nil
}

// LookupACLSubject validates an ID-space reference: that the kind is one
// we know and that the row it names exists.
//
// Granting to an ID with no row would leave a dangling reference, and
// IDs are never reused, so such a reference can only ever be a mistake.
func LookupACLSubject(db *gorm.DB, subject ACLSubject) (ACLSubject, error) {
	switch subject.Type {
	case ACLSubjectAuthenticated:
		// The sentinel names no row; an ID on it is meaningless, so
		// normalise it away rather than storing something that would
		// never be matched.
		return ACLSubject{Type: ACLSubjectAuthenticated}, nil
	case ACLSubjectGroup, ACLSubjectUser:
	default:
		return ACLSubject{}, fmt.Errorf("%w: unknown subject type %q", ErrUnknownACLSubject, subject.Type)
	}
	if db == nil {
		return ACLSubject{}, errors.New("database is required to resolve an ACL subject")
	}
	if subject.ID == "" {
		return ACLSubject{}, fmt.Errorf("%w: a %s subject needs an ID", ErrUnknownACLSubject, subject.Type)
	}
	var err error
	if subject.Type == ACLSubjectGroup {
		err = db.Select("id").Where("id = ?", subject.ID).First(&Group{}).Error
	} else {
		err = db.Select("id").Where("id = ?", subject.ID).First(&User{}).Error
	}
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ACLSubject{}, fmt.Errorf("%w: no %s with ID %q", ErrUnknownACLSubject, subject.Type, subject.ID)
		}
		return ACLSubject{}, err
	}
	return subject, nil
}

// AnnotateACLSubjects fills the display-only SubjectName / GroupID
// fields on ACL rows read out of the database, resolving each row's
// SubjectID through the `users` / `groups` tables in two batched
// queries. The stored row carries IDs only; these fields exist so the
// API can render a human-readable target (and so the legacy `groupId`
// wire field keeps its historical meaning for existing clients).
//
// A subject whose row has since been deleted resolves to an empty
// name — the grant no longer matches anybody either, so showing a
// blank target is honest.
func AnnotateACLSubjects(db *gorm.DB, acls []CollectionACL) error {
	if db == nil || len(acls) == 0 {
		return nil
	}
	userIDs := []string{}
	groupIDs := []string{}
	for _, a := range acls {
		switch a.SubjectType {
		case ACLSubjectUser:
			userIDs = append(userIDs, a.SubjectID)
		case ACLSubjectGroup:
			groupIDs = append(groupIDs, a.SubjectID)
		}
	}
	userCards, err := GetUserCards(db, userIDs)
	if err != nil {
		return err
	}
	groupCards, err := GetGroupCards(db, groupIDs)
	if err != nil {
		return err
	}
	for i := range acls {
		switch acls[i].SubjectType {
		case ACLSubjectAuthenticated:
			acls[i].SubjectName = AllAuthenticatedUsersACLGroup
			acls[i].GroupID = AllAuthenticatedUsersACLGroup
		case ACLSubjectUser:
			if c, ok := userCards[acls[i].SubjectID]; ok {
				acls[i].SubjectName = c.Username
				acls[i].GroupID = PersonalACLGroupPrefix + c.Username
			}
		case ACLSubjectGroup:
			if c, ok := groupCards[acls[i].SubjectID]; ok {
				acls[i].SubjectName = c.Name
				acls[i].GroupID = c.Name
			}
		}
	}
	return nil
}

// Collection — origin-local record of a curated namespace. Ownership
// model (per the user/group-design rewrite):
//
//   - OwnerID — the immutable User.ID of the collection's single
//     owner, and the ONLY ownership handle. The `owner` username
//     column this row used to carry was removed in migration
//     20260916120000: it was consulted as an authorization fallback,
//     so a PATCH transfer (which wrote owner_id alone) left the
//     previous owner in control, and a renamed or deleted account left
//     a claimable username behind (issue #3753). The owner's username
//     for display comes from the `users` row via GetUserCards.
//   - AdminID — the Group.ID of an OPTIONAL admin group whose members
//     can manage the collection day-to-day: edit metadata, manage
//     read/write ACLs, manage members, and reassign the admin group
//     itself. They CANNOT transfer ownership or delete the collection
//     — those stay owner-exclusive so an admin-group member can't
//     seize or destroy the row out from under the rightful owner.
//     Empty when no admin group is configured.
//   - ACLs — read/write groups attached via CollectionACL rows. The
//     deprecated AclRoleOwner role is tolerated on legacy rows but no
//     longer mints; ownership/admin authority comes from the row's
//     Owner/AdminID fields.
//
// Visibility=public collections are readable by anyone; private ones
// require Owner / admin-group / ACL membership / collection_admin scope.
type Collection struct {
	ID          string `gorm:"primaryKey" json:"id"`
	Name        string `gorm:"not null;uniqueIndex:idx_owner_name" json:"name"`
	Description string `json:"description"`
	// OwnerID pairs with Name in the unique index: one owner may not
	// have two collections of the same name. The production index is
	// PARTIAL (`WHERE owner_id <> ''`) so the legacy rows whose owner
	// never resolved to a user don't collide with each other; GORM's
	// AutoMigrate (tests only) can't express that, which is harmless
	// because fixtures always set an owner.
	OwnerID    string     `gorm:"not null;default:'';uniqueIndex:idx_owner_name" json:"ownerId"`
	AdminID    string     `gorm:"not null;default:''" json:"adminId"`
	Namespace  string     `gorm:"not null" json:"namespace"`
	Visibility Visibility `gorm:"not null;default:private" json:"visibility"`
	// EnableSharing is the operator-set opt-in that lets read-access
	// holders mint a "share" — a child collection that delegates a
	// subset of this collection's access. Defaults false; flipped only
	// by the collection owner / admin-group / collection_admin via
	// PATCH. The share self-service endpoint refuses to create a child
	// collection when the parent has EnableSharing == false.
	EnableSharing bool `gorm:"not null;default:false" json:"enableSharing"`
	// ParentCollectionID, when non-empty, marks this row as a *share*
	// of the named collection. Per the design (see
	// docs/collections-design.md), shares delegate a subset of the
	// parent's access to whoever the share is handed to; access-token
	// minting clamps the share's effective scopes by the share owner's
	// CURRENT access to the parent, so revocation propagates. Set only
	// by the share self-service endpoint; immutable thereafter.
	// The partial index on this column is created by the migration
	// (universal_migrations/20260502165710_collection_parent_id.sql);
	// not declaring it on the struct keeps GORM AutoMigrate from
	// trying to recreate it as a non-partial index in tests that
	// rely on AutoMigrate alone.
	ParentCollectionID string               `gorm:"not null;default:''" json:"parentCollectionId,omitempty"`
	CreatedAt          time.Time            `gorm:"not null;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt          time.Time            `gorm:"not null;default:CURRENT_TIMESTAMP" json:"updatedAt"`
	Members            []CollectionMember   `gorm:"foreignKey:CollectionID" json:"members"`
	ACLs               []CollectionACL      `gorm:"foreignKey:CollectionID" json:"acls"`
	Metadata           []CollectionMetadata `gorm:"foreignKey:CollectionID" json:"metadata"`
}

type CollectionMember struct {
	CollectionID string `gorm:"primaryKey" json:"collectionId"`
	ObjectURL    string `gorm:"primaryKey" json:"objectUrl"` // full pelican:// URL
	// AddedBy is a User.ID (or the 'unknown' audit sentinel), not a
	// username — see the note on CollectionACL.GrantedBy.
	AddedBy string    `gorm:"not null" json:"createdBy"`
	AddedAt time.Time `gorm:"not null;default:CURRENT_TIMESTAMP" json:"createdAt"`
}

// CollectionACL is one role grant on a collection. The grant target is
// the (SubjectType, SubjectID) pair — always an immutable ID, never a
// name. See ACLSubjectType for why.
//
// SubjectName and GroupID are NOT stored; AnnotateACLSubjects fills
// them in on the way out so the API can render a human-readable target
// without every consumer joining the users/groups tables itself.
type CollectionACL struct {
	CollectionID string         `gorm:"primaryKey" json:"collectionId"`
	SubjectType  ACLSubjectType `gorm:"primaryKey;not null" json:"subjectType"`
	SubjectID    string         `gorm:"primaryKey;not null;default:''" json:"subjectId"`
	Role         AclRole        `gorm:"primaryKey;not null" json:"role"`
	// GrantedBy is a User.ID (or the 'unknown' audit sentinel). It used
	// to hold a username; migration 20260916120000 converted it so that
	// no column in these tables mixes the two kinds of handle.
	GrantedBy string     `gorm:"not null" json:"createdBy"`
	GrantedAt time.Time  `gorm:"not null;default:CURRENT_TIMESTAMP" json:"createdAt"`
	ExpiresAt *time.Time `json:"expiresAt"`

	// SubjectName is the current display handle of the subject: a group
	// name, a username, or the `@authenticated` sentinel. Empty when the
	// subject row no longer exists.
	SubjectName string `gorm:"-" json:"subjectName"`
	// GroupID is the legacy wire spelling of the target — the group
	// name, `user-<username>`, or `@authenticated` — kept so existing
	// API clients (the web UI's revoke button, the CLI) keep working
	// unchanged. It is derived from SubjectName; nothing reads it back.
	GroupID string `gorm:"-" json:"groupId"`
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

// GroupAdminStatus latches what Pelican has established about an
// account's group-derived administrator privileges. It exists so that
// "we have not checked" is a state a guard can see, rather than a
// silence it has to interpret as "not an administrator" — which is how
// a server.user_admin came to be able to act on an administrator whose
// authority arrived in a provider's group assertion.
//
// The three states are ordered by how much they let a caller do, and
// only one transition is forbidden: nothing ever leaves
// GroupAdminPossible. See RecordGroupAdminObservation.
type GroupAdminStatus string

const (
	// GroupAdminUnknown — never established. Treated as a possible
	// administrator: refuse. The default, and what every account
	// carries until it is first observed.
	GroupAdminUnknown GroupAdminStatus = "unknown"
	// GroupAdminPossible — observed holding a group that confers an
	// administrator scope. Sticky: a provider retracting the membership
	// removes the evidence, not the history.
	GroupAdminPossible GroupAdminStatus = "possible"
	// GroupAdminRuledOut — groups observed, none of them administrative.
	GroupAdminRuledOut GroupAdminStatus = "ruled-out"
)

// MayBeAdmin reports whether this status requires treating the account
// as a possible administrator. Both "we saw one" and "we have not
// looked" do.
func (s GroupAdminStatus) MayBeAdmin() bool {
	return s != GroupAdminRuledOut
}

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
	ID          string     `gorm:"primaryKey" json:"id"`
	Username    string     `gorm:"not null;uniqueIndex:idx_user_username_live" json:"username"`
	Sub         string     `gorm:"not null;uniqueIndex:idx_user_sub_issuer" json:"sub"`
	Issuer      string     `gorm:"not null;uniqueIndex:idx_user_sub_issuer" json:"issuer"`
	Status      UserStatus `gorm:"not null;default:active" json:"status"`
	LastLoginAt *time.Time `json:"lastLoginAt"`
	DisplayName string     `gorm:"not null;default:''" json:"displayName"`
	AUPVersion  string     `gorm:"not null;default:''" json:"aupVersion"`
	AUPAgreedAt *time.Time `json:"aupAgreedAt"`
	// GroupAdminStatus latches what has been established about this
	// account's group-derived administrator privileges; see the type.
	// Consulted only by the guard that stops a user-administrator from
	// acting on an administrator's account — never to GRANT anything.
	GroupAdminStatus GroupAdminStatus `gorm:"not null;default:'unknown'" json:"groupAdminStatus"`
	// GroupsObservedAt is when this account's provider-asserted group
	// set was last reconciled, or NULL if it never has been. Says when
	// the observation happened; GroupAdminStatus says what it concluded.
	GroupsObservedAt *time.Time `json:"groupsObservedAt,omitempty"`
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
// batch the lookup with a single "id IN ? AND password_hash <> ”"
// query.
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

// GroupSource names *which* provider a Group record came from. There is
// no "internal vs external" split: Pelican reads group membership from
// several providers, they behave differently from each other, and an
// operator debugging "why is this user in this group" needs to know
// which one to go look at. The values line up one-for-one with
// `Issuer.GroupSource` so the config value and the recorded provenance
// read the same.
//
//   - GroupSourcePelican — created through Pelican's own group-management
//     API. `group_members` is authoritative for its membership. This is
//     the only source a user can create a group in.
//   - GroupSourceOIDC — asserted in the identity provider's group claim.
//   - GroupSourceFile — listed in `Issuer.GroupFile`.
//   - GroupSourceGitHub — a GitHub organization.
//   - GroupSourceUnknown — the record was backfilled by migration
//     20260916120000 from a collection ACL that named a group Pelican
//     had no record of. Some provider asserts the name, but which one is
//     not recoverable from the old schema; the next assertion stamps the
//     real provider.
//
// Every value but GroupSourcePelican is *asserted*: the named provider,
// not this server, decides who is in the group. See IsAsserted.
type GroupSource string

const (
	GroupSourcePelican GroupSource = "pelican"
	GroupSourceOIDC    GroupSource = "oidc"
	GroupSourceFile    GroupSource = "file"
	GroupSourceGitHub  GroupSource = "github"
	GroupSourceUnknown GroupSource = "unknown"
)

// Group source types: the spellings Issuer.GroupSource accepts in the
// configuration file. ConfiguredGroupSource maps them onto the
// GroupSource values above.
const (
	GroupSourceTypeOIDC     string = "oidc"
	GroupSourceTypeFile     string = "file"
	GroupSourceTypeInternal string = "internal"
	GroupSourceTypeGitHub   string = "github"
)

// ConfiguredGroupSource maps Issuer.GroupSource onto the GroupSource a
// record is stamped with. It is the single answer to "who decides group
// membership on this server", and every path that learns a caller's
// groups must route through it.
//
// Single-valued, deliberately. The group file used to be read on the
// password-login and init-code paths whatever Issuer.GroupSource said,
// which made `file` an always-on second provider layered under `oidc`
// or `github`. That asymmetry is what let a file with no entry for an
// OIDC account be treated as an authoritative statement that the
// account is in no groups — see RecordAssertedGroups and the latch in
// RecordGroupAdminObservation.
//
// GroupSourcePelican is returned for the `internal` source: membership
// is Pelican's own, held in group_members, and nothing needs mirroring.
// The empty GroupSource means no provider decides groups here.
func ConfiguredGroupSource() GroupSource {
	switch strings.ToLower(param.Issuer_GroupSource.GetString()) {
	case GroupSourceTypeOIDC:
		return GroupSourceOIDC
	case GroupSourceTypeFile:
		return GroupSourceFile
	case GroupSourceTypeGitHub:
		return GroupSourceGitHub
	case GroupSourceTypeInternal:
		return GroupSourcePelican
	}
	return ""
}

// IsAsserted reports whether membership of a group from this source is
// decided by an outside provider rather than by `group_members`. Such
// groups are owned by the built-in admin, cannot be renamed (the name is
// what the provider's assertion is matched against), and hold their name
// against a would-be local group of the same name.
func (s GroupSource) IsAsserted() bool {
	return s != "" && s != GroupSourcePelican
}

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
	ID string `gorm:"primaryKey" json:"id"`
	// The production uniqueness index is PARTIAL (`WHERE deleted_at IS
	// NULL`), created by migration 20260917120000 so a deleted group
	// releases its name. Declared as a named uniqueIndex rather than
	// `unique` so AutoMigrate (tests only) emits a droppable index
	// instead of an inline column constraint, which SQLite backs with an
	// undroppable implicit index — setupCollectionTestDB replaces it
	// with the partial shape.
	Name                string     `gorm:"not null;uniqueIndex:idx_groups_name_live" json:"name"`
	DisplayName         string     `gorm:"not null;default:''" json:"displayName"`
	Description         string     `json:"description"`
	CreatedBy           string     `gorm:"not null" json:"createdBy"`
	CreatorAuthMethod   AuthMethod `gorm:"not null;default:''" json:"creatorAuthMethod"`
	CreatorAuthMethodID string     `gorm:"not null;default:''" json:"creatorAuthMethodId,omitempty"`
	OwnerID             string     `gorm:"not null;default:''" json:"ownerId"`
	AdminID             string     `gorm:"not null;default:''" json:"adminId"`
	AdminType           AdminType  `gorm:"not null;default:''" json:"adminType"`
	// AuthTemplateEligible gates whether this group is allowed to
	// match against Issuer.AuthorizationTemplates and the
	// Server.*AdminGroups config lists at runtime. Group creation is
	// open to any authenticated user so they can mint groups for their
	// own collection ACLs / shares; the bit prevents a self-named
	// group from also gaining authz-template authority. Only an
	// admin / user-admin can set or flip the bit. Pre-existing rows
	// (before the open-creation rollout) are migrated to true since
	// they were minted by an admin and operators expect them to keep
	// matching templates.
	// gorm:"not null" without a `default:` tag — the SQL default (TRUE
	// for backfill of pre-existing rows) lives in the migration. Adding
	// `default:true` here would make GORM substitute the default on
	// every insert with a zero Go value, defeating the create-time
	// non-admin clamp ("AuthTemplateEligible: false" would round-trip
	// as true).
	AuthTemplateEligible bool `gorm:"not null" json:"authTemplateEligible"`
	// Source names which provider this record came from —
	// GroupSourcePelican for one created through the group-management
	// API, or the identity provider that asserted the name (see
	// EnsureAssertedGroups and the GroupSource doc comment). An asserted
	// record is minted automatically on first observation and owned by
	// the built-in admin user; it exists to give the name a stable ID
	// that ACLs can key on, and to hold the name against an
	// unprivileged user creating a group that shadows it.
	Source GroupSource `gorm:"not null;default:'pelican'" json:"source"`
	// CreatedForCollectionID marks groups minted alongside a specific
	// collection during the onboarding flow. The redemption path of a
	// collection-ownership invite cascades the transfer to every group
	// where this field equals the collection being transferred AND the
	// group's current owner still matches the collection's previous
	// owner — that "AND owner unchanged" guard avoids yanking a group
	// out from under a downstream operator who already re-homed it.
	CreatedForCollectionID string        `gorm:"not null;default:''" json:"createdForCollectionId,omitempty"`
	CreatedAt              time.Time     `gorm:"not null;default:CURRENT_TIMESTAMP" json:"createdAt"`
	UpdatedAt              time.Time     `gorm:"not null;default:CURRENT_TIMESTAMP" json:"updatedAt"`
	Members                []GroupMember `gorm:"foreignKey:GroupID" json:"members"`
	// DeletedAt is the soft-delete tombstone, mirroring User.DeletedAt.
	// A Group.ID is an authorization handle, so it must never be reused:
	// generateSlug picks 8 hex characters with no uniqueness check, and
	// a hard delete freed the ID for a later group to be minted with,
	// silently inheriting whatever still referenced it. Keeping the row
	// spends the ID permanently and leaves historical references
	// (created_by, audit trails) resolvable, while GORM's default scope
	// hides it from every ordinary query so it confers nothing. The
	// NAME is released — see the migration — because nothing keys on a
	// group name any more.
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

// GroupMember is one user's membership in one group. There is at most
// one row per (group, user) regardless of how the membership arose; see
// Source for how the two kinds interact.
type GroupMember struct {
	GroupID string    `gorm:"primaryKey" json:"groupId"`
	UserID  string    `gorm:"primaryKey;index" json:"userId"`
	User    User      `gorm:"foreignKey:UserID" json:"user"`
	AddedBy string    `gorm:"not null" json:"createdBy"`
	AddedAt time.Time `gorm:"not null;default:CURRENT_TIMESTAMP" json:"createdAt"`
	// Source distinguishes a membership an administrator created through
	// the group API (GroupSourcePelican — authoritative, never expires)
	// from one mirrored out of a provider's assertion (any other value,
	// naming that provider). A Pelican membership always wins: an
	// assertion never overwrites or expires one, so an admin who adds a
	// local member to an asserted group keeps them.
	Source GroupSource `gorm:"not null;default:'pelican'" json:"source"`
	// AssertedAt is when the provider last asserted this membership, and
	// is NULL on Pelican-created rows. A mirrored row may only GRANT
	// while it is fresh — see MirroredMembershipTTL and
	// freshAssertedMembershipCutoff — but it is KEPT once stale, because
	// a consumer asking a restricting question ("might this account be an
	// admin?") must still see it. Rows disappear only when the provider
	// stops asserting the membership.
	AssertedAt *time.Time `json:"assertedAt,omitempty"`
}

// IsMirrored reports whether this membership came from a provider's
// assertion rather than from the group-management API.
func (m GroupMember) IsMirrored() bool {
	return m.Source.IsAsserted()
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
//   - InviteKindCollectionOwnership: redeem-time, the *caller's* user
//     becomes the owner of CollectionID. The previous owner stays a
//     row-level audit reference (Collection.CreatedBy / created_by
//     audit), but Collection.OwnerID and Collection.Owner are
//     overwritten with the redeemer's identity. Caller must be
//     authenticated — we need a real user to transfer ownership to.
//     Forced single-use: ownership transfer is by definition a
//     one-shot operation.
//   - InviteKindRegistrationOwnership: redeem-time, the *caller's* user
//     becomes the owner of the registry registration named by
//     RegistrationID (their Pelican User.ID is written into the
//     registration's admin metadata). Caller must be authenticated.
//     Forced single-use, mirroring collection-ownership invites.
type InviteKind string

const (
	InviteKindGroup                 InviteKind = "group"
	InviteKindPassword              InviteKind = "password"
	InviteKindCollectionOwnership   InviteKind = "collection_ownership"
	InviteKindRegistrationOwnership InviteKind = "registration_ownership"
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
	ID   string     `gorm:"primaryKey" json:"id"`
	Kind InviteKind `gorm:"not null;default:'group';index:idx_invite_links_kind" json:"kind"`
	// GroupID is set when Kind == InviteKindGroup. Empty otherwise.
	GroupID string `gorm:"not null;default:''" json:"groupId"`
	// TargetUserID is set when Kind == InviteKindPassword. Empty otherwise.
	// (For group invites the user is whoever redeems; for password invites
	// the user is fixed at link creation time and the redeemer must not be
	// allowed to set a different account's password.)
	TargetUserID string `gorm:"not null;default:'';index:idx_invite_links_target_user" json:"targetUserId"`
	// CollectionID is set when Kind == InviteKindCollectionOwnership;
	// names the collection whose ownership transfers to the redeemer.
	// Empty for every other kind.
	CollectionID string `gorm:"not null;default:''" json:"collectionId"`
	// RegistrationID is set when Kind == InviteKindRegistrationOwnership;
	// names the registry registration whose ownership transfers to the
	// redeemer. Zero for every other kind.
	RegistrationID int    `gorm:"not null;default:0" json:"registrationId"`
	HashedToken    string `gorm:"column:invite_token;not null;unique" json:"-"`
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

// CreateCollection persists a new collection row owned by `ownerID`
// (a User.ID slug — the only ownership handle; see the Collection
// doc comment). The row's own OwnerID/AdminID fields encode
// authority — the function does not auto-mint an AclRoleOwner ACL
// row, so ACL listings are not polluted with an owner pseudo-grant.
//
// `ownerID` may be empty for legacy/test paths that don't have a
// User record handy; in that case the collection has an empty
// OwnerID and ownership-checks fall through to admin-group / ACL /
// admin-scope paths. New code SHOULD always supply a real User.ID.
func CreateCollection(db *gorm.DB, name, description, ownerID, namespace string, visibility Visibility) (*Collection, error) {
	slug, err := generateSlug()
	if err != nil {
		return nil, err
	}

	collection := &Collection{
		ID:          slug,
		Name:        name,
		Description: description,
		OwnerID:     ownerID,
		Namespace:   namespace,
		Visibility:  visibility,
	}

	err = db.Transaction(func(tx *gorm.DB) error {
		if result := tx.Create(collection); result.Error != nil {
			return result.Error
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return collection, nil
}

// CreateCollectionWithMetadata is the create path used by the HTTP
// handlers — takes the same `ownerID` as CreateCollection
// plus an optional metadata map persisted in the same transaction.
// `enableSharing` opts the collection in to user-driven shares; the
// flag can also be flipped after creation via UpdateCollection.
func CreateCollectionWithMetadata(db *gorm.DB, name, description, ownerID, namespace string, visibility Visibility, enableSharing bool, metadata map[string]string) (*Collection, error) {
	slug, err := generateSlug()
	if err != nil {
		return nil, err
	}

	collection := &Collection{
		ID:            slug,
		Name:          name,
		Description:   description,
		OwnerID:       ownerID,
		Namespace:     namespace,
		Visibility:    visibility,
		EnableSharing: enableSharing,
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

		return nil
	})

	if err != nil {
		return nil, err
	}

	return collection, nil
}

// ListCollections returns every collection the caller can see. The
// visibility set is the union of:
//
//  1. Public collections (visibility=public).
//  2. Collections the caller owns, matched on OwnerID. Without this
//     branch a freshly-transferred owner's listing comes up empty: the
//     row carries no read ACL for them, and the auto-owner ACL is gone
//     per the ownership-model rewrite, so OwnerID is the *only* link
//     between the user and the row.
//  3. Collections whose admin-group the caller belongs to. Membership
//     is resolved to Group.IDs by ResolveCallerACLSubjects, which
//     unions `group_members` rows with the caller's provider-asserted
//     group names, so both sources are covered by one `admin_id IN ?`.
//  4. Collections with a read-eligible ACL row naming one of the
//     caller's subjects (their user, one of their groups, or the
//     all-authenticated sentinel).
//
// Admins (server.admin / server.collection_admin) bypass and get
// global visibility — the management endpoints already do this and the
// list should match so admin-as-investigator works.
func ListCollections(db *gorm.DB, user, userID string, groups []string, isAdmin bool) ([]Collection, error) {
	if isAdmin {
		var all []Collection
		if result := db.Find(&all); result.Error != nil {
			return nil, result.Error
		}
		return all, nil
	}

	// Resolve the caller to their ID-keyed subject set once; every
	// branch below matches on IDs. Mirrors validateACL /
	// GetUserCollectionScopes.
	subjects := ResolveCallerACLSubjects(db, user, userID, groups)

	out := []Collection{}
	seen := make(map[string]struct{})
	addAll := func(rows []Collection) {
		for _, r := range rows {
			if _, ok := seen[r.ID]; ok {
				continue
			}
			seen[r.ID] = struct{}{}
			out = append(out, r)
		}
	}

	// (1) Public collections.
	var pub []Collection
	if err := db.Where("visibility = ?", VisibilityPublic).Find(&pub).Error; err != nil {
		return nil, err
	}
	addAll(pub)

	// (2) Owned collections, matched on the immutable User.ID.
	if subjects.UserID != "" {
		var owned []Collection
		if err := db.Where("owner_id = ?", subjects.UserID).Find(&owned).Error; err != nil {
			return nil, err
		}
		addAll(owned)
	}

	// (3) Admin-group membership. subjects.GroupIDs already unions the
	// `group_members` rows with the caller's asserted group names.
	if len(subjects.GroupIDs) > 0 {
		var viaAdminGroup []Collection
		if err := db.Where("admin_id IN ?", subjects.GroupIDs).Find(&viaAdminGroup).Error; err != nil {
			return nil, err
		}
		addAll(viaAdminGroup)
	}

	// (4) ACL-granted read access.
	if where, args := subjects.ACLWhere(); where != "" {
		var aclCollections []Collection
		if err := db.
			Joins("JOIN collection_acls ON collections.id = collection_acls.collection_id").
			Where(where, args...).
			Where("collection_acls.role IN ?", ScopeToRole[token_scopes.Collection_Read]).
			Find(&aclCollections).Error; err != nil {
			return nil, err
		}
		addAll(aclCollections)
	}

	return out, nil
}

func GetCollection(db *gorm.DB, id string, user, userID string, groups []string, isAdmin bool) (*Collection, error) {
	collection := &Collection{}
	if result := db.Preload("Members").Preload("ACLs").Preload("Metadata").Where("id = ?", id).First(collection); result.Error != nil {
		return nil, result.Error
	}

	// Admin bypass: matches ListCollections / UpdateCollection / etc.
	// A system or collection admin reading any single collection
	// follows the same "you can manage anything" posture they have
	// elsewhere; without this branch a system admin couldn't open the
	// collection page for a private collection unless they also held
	// a read ACL on it.
	if isAdmin {
		return collection, nil
	}

	if collection.Visibility == VisibilityPublic {
		return collection, nil
	}

	err := validateACL(db, collection, user, userID, groups, token_scopes.Collection_Read)
	if err != nil {
		return nil, err
	}

	return collection, nil
}

func GetCollectionMembers(db *gorm.DB, id, user, userID string, groups []string, since *time.Time, limit int) ([]CollectionMember, error) {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return nil, result.Error
	}

	err := validateACL(db, collection, user, userID, groups, token_scopes.Collection_Read)
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

func GetCollectionMetadata(db *gorm.DB, id, user, userID string, groups []string) ([]CollectionMetadata, error) {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return nil, result.Error
	}

	err := validateACL(db, collection, user, userID, groups, token_scopes.Collection_Read)
	if err != nil {
		return nil, err
	}

	metadata := []CollectionMetadata{}
	if result := db.Where("collection_id = ?", id).Find(&metadata); result.Error != nil {
		return nil, result.Error
	}
	return metadata, nil
}

func GetCollectionAcls(db *gorm.DB, id, user, userID string, groups []string, isAdmin bool) ([]CollectionACL, error) {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return nil, result.Error
	}

	// Admin bypass mirrors GetCollection's: a system or collection
	// admin can read the ACL list for any collection they can see in
	// the listing. Without this, an admin viewing a collection they
	// don't own — and that has no Collection_Modify-scope ACL row to
	// match against — would get a misleading "collection not found"
	// 404 on every expand / edit-page open.
	if isAdmin {
		if err := AnnotateACLSubjects(db, collection.ACLs); err != nil {
			return nil, err
		}
		return collection.ACLs, nil
	}

	// The spec says that owners and writers should be able to see the ACLs.
	// We can reuse the Collection_Modify scope for this.
	err := validateACL(db, collection, user, userID, groups, token_scopes.Collection_Modify)
	if err != nil {
		return nil, err
	}

	if err := AnnotateACLSubjects(db, collection.ACLs); err != nil {
		return nil, err
	}
	return collection.ACLs, nil
}

// GrantCollectionAcl adds (or refreshes) a role grant on a collection.
//
// `ref` is a NAME-space target: a group name, `user-<username>`, or the
// `@authenticated` sentinel. Callers holding an ID use
// GrantCollectionAclBySubject instead — the two spaces have separate
// entry points so neither has to be guessed from the string. A
// reference that matches nothing is rejected with ErrUnknownACLSubject
// rather than persisted verbatim.
func GrantCollectionAcl(db *gorm.DB, id, user, userID string, groups []string, ref ACLSubjectRef, role AclRole, expiresAt *time.Time, isAdmin bool) error {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return result.Error
	}

	if !isAdmin {
		err := validateACL(db, collection, user, userID, groups, token_scopes.Collection_Delete)
		if err != nil {
			return err
		}
	}

	subject, err := ResolveACLSubjectRef(db, ref)
	if err != nil {
		return err
	}
	return GrantCollectionAclBySubject(db, id, user, userID, groups, subject, role, expiresAt, isAdmin)
}

// GrantCollectionAclBySubject is the ID-space counterpart of
// GrantCollectionAcl: the caller supplies the stored subject directly,
// so there is no name to resolve and nothing to guess. This is the only
// way to grant to a *user* by ID.
func GrantCollectionAclBySubject(db *gorm.DB, id, user, userID string, groups []string, subject ACLSubject, role AclRole, expiresAt *time.Time, isAdmin bool) error {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return result.Error
	}

	if !isAdmin {
		if err := validateACL(db, collection, user, userID, groups, token_scopes.Collection_Delete); err != nil {
			return err
		}
	}

	subject, err := LookupACLSubject(db, subject)
	if err != nil {
		return err
	}

	return db.Transaction(func(tx *gorm.DB) error {
		acl := CollectionACL{
			CollectionID: id,
			SubjectType:  subject.Type,
			SubjectID:    subject.ID,
			Role:         role,
			GrantedBy:    creatorOrUnknown(userID),
			ExpiresAt:    expiresAt,
		}
		// Use OnConflict to either create or update the ACL
		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "collection_id"}, {Name: "subject_type"}, {Name: "subject_id"}, {Name: "role"}},
			DoUpdates: clause.AssignmentColumns([]string{"granted_by", "expires_at"}),
		}).Create(&acl).Error
	})
}

// RevokeCollectionAcl removes a role grant named in the NAME space —
// the same spellings GrantCollectionAcl accepts, including the `groupId`
// value the API hands back on a listing, so a client can round-trip what
// it read.
func RevokeCollectionAcl(db *gorm.DB, id, user, userID string, groups []string, ref ACLSubjectRef, role AclRole, isAdmin bool) error {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return result.Error
	}

	if !isAdmin {
		err := validateACL(db, collection, user, userID, groups, token_scopes.Collection_Delete)
		if err != nil {
			return err
		}
	}

	subject, err := ResolveACLSubjectRef(db, ref)
	if err != nil {
		return err
	}
	return RevokeCollectionAclBySubject(db, id, user, userID, groups, subject, role, isAdmin)
}

// RevokeCollectionAclBySubject is the ID-space counterpart of
// RevokeCollectionAcl. It is also the only way to clear a row whose
// subject has since been deleted, since there is no name left to
// resolve — so unlike the grant path it does NOT require the subject to
// still exist.
func RevokeCollectionAclBySubject(db *gorm.DB, id, user, userID string, groups []string, subject ACLSubject, role AclRole, isAdmin bool) error {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return result.Error
	}

	if !isAdmin {
		if err := validateACL(db, collection, user, userID, groups, token_scopes.Collection_Delete); err != nil {
			return err
		}
	}

	switch subject.Type {
	case ACLSubjectGroup, ACLSubjectUser:
	case ACLSubjectAuthenticated:
		subject.ID = ""
	default:
		return fmt.Errorf("%w: unknown subject type %q", ErrUnknownACLSubject, subject.Type)
	}

	return db.Transaction(func(tx *gorm.DB) error {
		if result := tx.Where("collection_id = ? AND subject_type = ? AND subject_id = ? AND role = ?",
			id, subject.Type, subject.ID, role).Delete(&CollectionACL{}); result.Error != nil {
			return result.Error
		}
		return nil
	})
}

func UpsertCollectionMetadata(db *gorm.DB, id, user, userID string, groups []string, key, value string, isAdmin bool) error {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return result.Error
	}

	if !isAdmin {
		err := validateACL(db, collection, user, userID, groups, token_scopes.Collection_Modify)
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

func DeleteCollectionMetadata(db *gorm.DB, id, user, userID string, groups []string, key string, isAdmin bool) error {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return result.Error
	}

	if !isAdmin {
		err := validateACL(db, collection, user, userID, groups, token_scopes.Collection_Modify)
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

// ErrSharingDisabled means the parent collection has not opted into
// user-driven shares (Collection.EnableSharing == false). Surface
// this from the share-create handler as a 409 — refusing is correct,
// but the caller should know it's a deliberate opt-out, not an
// authorization issue.
var ErrSharingDisabled = errors.New("sharing is not enabled on this collection")

// CreateShareReq is the input for CreateShare. Mirrors
// CreateCollectionWithMetadata's positional arguments but bundles
// share-specific fields (the parent + the share-owner identity) and
// dis-allows the operator-only knobs (no admin group, no
// enable-sharing flag, no metadata) on the create path. A share owner
// can set those later via the regular PATCH surface if they hold the
// owner gate on the share itself.
type CreateShareReq struct {
	ParentCollectionID string
	Name               string
	Description        string
	Namespace          string
	Visibility         Visibility
	// OwnerID — the share is owned by the caller minting it, not by
	// the parent collection's owner. Per the design, access tokens for
	// the share's prefixes are clamped to whatever the share owner
	// currently has on the parent — that intersection happens at
	// token-mint time (see oa4mp), not here.
	OwnerID string
}

// CreateShare persists a new share — a child Collection whose
// `parent_collection_id` is the parent's ID. Authorization is the
// caller's responsibility; this helper enforces only the data-model
// invariants:
//
//   - The parent must exist.
//   - The parent must have EnableSharing == true (else
//     ErrSharingDisabled, distinct from ErrForbidden so the handler
//     can surface a clearer message than "not found").
//   - The supplied namespace must be a prefix-or-equal of the
//     parent's namespace — you can't delegate access you don't have.
//
// The handler is expected to enforce: caller has Collection_Read on
// the parent, AND the configured Origin storage backend is not
// multi-user (impersonation isn't supported there per the design).
//
// The new share starts with no ACLs, no admin group, and
// EnableSharing = false. The share owner is free to add ACLs after
// the fact (they hold owner authority on the row).
func CreateShare(db *gorm.DB, req CreateShareReq) (*Collection, error) {
	if req.ParentCollectionID == "" {
		return nil, errors.New("parent collection id is required")
	}
	if req.Name == "" {
		return nil, errors.New("share name is required")
	}
	if req.Visibility != VisibilityPublic && req.Visibility != VisibilityPrivate {
		return nil, errors.New("share visibility must be 'public' or 'private'")
	}

	var parent Collection
	if err := db.Where("id = ?", req.ParentCollectionID).First(&parent).Error; err != nil {
		return nil, err
	}
	if !parent.EnableSharing {
		return nil, ErrSharingDisabled
	}
	// Shares of shares are not supported in the current design — the
	// intersection logic at token-mint time only walks one hop. If
	// later we want recursive sharing, this guard is the place to
	// drop and the mint-time intersection is the place to teach.
	if parent.ParentCollectionID != "" {
		return nil, errors.New("cannot create a share of an existing share")
	}

	// Namespace must equal the parent's or be a path-descendant.
	// Canonicalize (and reject scope-corrupting characters) BEFORE the
	// prefix comparison so the descendant check and the later scope mint
	// operate on the same value — otherwise a traversal like
	// "/parent/../../secret" would slip past the prefix check here and
	// clean to "/secret" at mint time. Empty namespace defaults to the
	// parent's exact namespace.
	parentNS := strings.TrimRight(parent.Namespace, "/")
	var ns string
	if strings.TrimRight(req.Namespace, "/") == "" {
		ns = parentNS
	} else {
		cleaned, err := CleanNamespacePath(req.Namespace)
		if err != nil {
			return nil, err
		}
		ns = strings.TrimRight(cleaned, "/")
	}
	if ns != parentNS && !strings.HasPrefix(ns, parentNS+"/") {
		return nil, errors.New("share namespace must equal or be a path-descendant of the parent's namespace")
	}

	slug, err := generateSlug()
	if err != nil {
		return nil, err
	}
	share := &Collection{
		ID:                 slug,
		Name:               req.Name,
		Description:        req.Description,
		OwnerID:            req.OwnerID,
		Namespace:          ns,
		Visibility:         req.Visibility,
		ParentCollectionID: parent.ID,
		// EnableSharing intentionally false — see the comment above
		// about share-of-share.
	}
	if err := db.Create(share).Error; err != nil {
		return nil, err
	}
	return share, nil
}

// ListCollectionShares returns every collection that has its
// `parent_collection_id` set to the supplied parent ID — i.e. every
// share of that parent. The visibility filter mirrors
// ListCollections: an admin-bypass returns all shares, otherwise
// shares are filtered to the same {public, owned, admin-group, ACL}
// union as plain collections. The caller is expected to pass the
// already-fetched parent's authorisation gate elsewhere; this helper
// only filters its own results, so a private share inside a parent
// the caller can read still hides if the share's ACL doesn't admit
// them.
func ListCollectionShares(db *gorm.DB, parentID, user, userID string, groups []string, isAdmin bool) ([]Collection, error) {
	if parentID == "" {
		return nil, errors.New("parent collection id is required")
	}
	if isAdmin {
		var all []Collection
		if err := db.Where("parent_collection_id = ?", parentID).Find(&all).Error; err != nil {
			return nil, err
		}
		return all, nil
	}

	subjects := ResolveCallerACLSubjects(db, user, userID, groups)

	out := []Collection{}
	seen := map[string]struct{}{}
	addAll := func(rows []Collection) {
		for _, r := range rows {
			if _, ok := seen[r.ID]; ok {
				continue
			}
			seen[r.ID] = struct{}{}
			out = append(out, r)
		}
	}

	// (1) Public shares.
	var pub []Collection
	if err := db.Where("parent_collection_id = ? AND visibility = ?", parentID, VisibilityPublic).Find(&pub).Error; err != nil {
		return nil, err
	}
	addAll(pub)

	// (2) Owned shares, matched on the immutable User.ID.
	if subjects.UserID != "" {
		var owned []Collection
		if err := db.Where("parent_collection_id = ? AND owner_id = ?", parentID, subjects.UserID).Find(&owned).Error; err != nil {
			return nil, err
		}
		addAll(owned)
	}

	// (3) Admin-group membership (DB-recorded and asserted, unioned by
	// ResolveCallerACLSubjects).
	if len(subjects.GroupIDs) > 0 {
		var viaAdminGroup []Collection
		if err := db.Where("parent_collection_id = ? AND admin_id IN ?", parentID, subjects.GroupIDs).Find(&viaAdminGroup).Error; err != nil {
			return nil, err
		}
		addAll(viaAdminGroup)
	}

	// (4) ACL-granted read access.
	if where, args := subjects.ACLWhere(); where != "" {
		var aclRows []Collection
		if err := db.
			Joins("JOIN collection_acls ON collections.id = collection_acls.collection_id").
			Where("collections.parent_collection_id = ?", parentID).
			Where(where, args...).
			Where("collection_acls.role IN ?", ScopeToRole[token_scopes.Collection_Read]).
			Find(&aclRows).Error; err != nil {
			return nil, err
		}
		addAll(aclRows)
	}

	return out, nil
}

// UpdateCollection mutates the high-level fields of a collection.
// Owner-managed fields (OwnerID, AdminID) live on this same call so
// the edit-form can patch everything in one round-trip; transferring
// ownership and (re)assigning the admin group are restricted to
// callers who pass the existing-owner-or-admin gate (so the current
// owner can hand the collection to someone else, but a writer can't
// elevate themselves).
func UpdateCollection(db *gorm.DB, id, user, userID string, groups []string, name, description *string, visibility *Visibility, ownerID, adminID *string, enableSharing *bool, isAdmin bool) error {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return result.Error
	}

	if !isAdmin {
		err := validateACL(db, collection, user, userID, groups, token_scopes.Collection_Modify)
		if err != nil {
			return err
		}
		// Ownership transfer (ownerID) is owner-exclusive: an
		// admin-group member must NOT be able to seize the
		// collection by re-pointing OwnerID at themselves. The
		// privileged-scope bypass above already covers
		// server.collection_admin / admin, so this check only
		// runs for cookie callers without those scopes.
		//
		// Admin-group reassignment (adminID) stays available to
		// admin-group members — they're the people the owner
		// delegated management to, and changing the admin group is
		// part of "manage delegation". If that turns out to be too
		// permissive in practice we can tighten it later, but the
		// primary security concern (locking the rightful owner
		// out) is addressed by the ownerID gate.
		if ownerID != nil &&
			!CallerIsCollectionOwner(db, collection, user, userID) {
			return ErrForbidden
		}
		if adminID != nil &&
			!CallerIsCollectionOwnerOrAdmin(db, collection, user, userID, groups) {
			return ErrForbidden
		}
	}
	// Every collection must always have an owner. The data model
	// gives some helpers a "no-owner" fallback (validateACL falls
	// through to ACLs when OwnerID is empty), but a deliberate clear
	// via PATCH would silently strand the row — the previous owner
	// loses authority and no replacement is named, so no cookie
	// caller can manage it without a scope-admin bypass. Refuse it
	// here. The ownership-transfer-invite path (or a direct PATCH
	// with a non-empty ownerId) is the supported way to hand a
	// collection off.
	if ownerID != nil {
		if strings.TrimSpace(*ownerID) == "" {
			return errors.New("ownerId cannot be empty; transfer to a real user instead")
		}
		// And it has to name a live account. OwnerID is now the ONLY
		// ownership handle — there is no username column to fall back
		// on — so a typo'd or stale ID would strand the collection
		// exactly as an empty one would.
		if err := db.Select("id").Where("id = ?", *ownerID).First(&User{}).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("ownerId %q does not name an active user", *ownerID)
			}
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
	if ownerID != nil {
		updates["owner_id"] = *ownerID
	}
	if adminID != nil {
		updates["admin_id"] = *adminID
	}
	if enableSharing != nil {
		updates["enable_sharing"] = *enableSharing
	}

	if len(updates) == 0 {
		return nil
	}

	return db.Model(&Collection{}).Where("id = ?", id).Updates(updates).Error
}

func AddCollectionMembers(db *gorm.DB, id string, members []string, addedBy, addedByID string, groups []string, isAdmin bool) error {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return result.Error
	}

	if !isAdmin {
		err := validateACL(db, collection, addedBy, addedByID, groups, token_scopes.Collection_Modify)
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
			AddedBy:      creatorOrUnknown(addedByID),
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

func RemoveCollectionMembers(db *gorm.DB, id string, members []string, user, userID string, groups []string, isAdmin bool) error {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return result.Error
	}

	if !isAdmin {
		err := validateACL(db, collection, user, userID, groups, token_scopes.Collection_Modify)
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

func DeleteCollection(db *gorm.DB, id string, owner, ownerID string, groups []string, isAdmin bool) error {
	collection := &Collection{}
	if result := db.Preload("ACLs").Where("id = ?", id).First(collection); result.Error != nil {
		return result.Error
	}

	// Deletion is owner-exclusive (or system / collection-admin
	// scope, via the isAdmin bypass). Admin-group members can manage
	// members and ACLs but MUST NOT be able to dispose of the
	// collection — otherwise an admin-group member could destroy a
	// collection out from under its rightful owner. This intentionally
	// diverges from the older validateACL-based check, which let any
	// AclRoleOwner-row holder delete; under the new ownership model,
	// that role no longer exists and the owner is identified by
	// Collection.OwnerID.
	if !isAdmin {
		if !CallerIsCollectionOwner(db, collection, owner, ownerID) {
			return ErrForbidden
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

// rolePriority orders the ACL role values so callers can take the
// "higher" of two roles. Owner > Write > Read > "" (none). Stored as
// integers so EffectiveCollectionRole can return the maximum match
// across multiple ACL paths (admin-group, personal group, etc).
func rolePriority(r AclRole) int {
	switch r {
	case AclRoleOwner:
		return 3
	case AclRoleWrite:
		return 2
	case AclRoleRead:
		return 1
	}
	return 0
}

// MinRole returns whichever of the two roles is *lower*. Used by the
// share-token-mint intersection: a recipient's effective role on a
// share must be clamped by the share owner's CURRENT role on the
// parent collection — pick the weaker of the two so revocation
// propagates (the share owner losing write on the parent must not
// leave the recipient with write on the share).
func MinRole(a, b AclRole) AclRole {
	if rolePriority(a) <= rolePriority(b) {
		return a
	}
	return b
}

// EffectiveCollectionRole returns the highest ACL role the named
// user holds on the supplied collection, or "" when they hold none.
// Walks all the same paths CallerIsCollectionOwnerOrAdmin does
// (direct ownership, admin-group membership, ACL grants to the user
// or to a group they belong to, the all-authenticated-users sentinel)
// but does NOT consider session-asserted group names — the caller is
// identified by their stable User row, not their current session.
//
// Used by the share-token-mint intersection: the data plane mints
// `share.access:/$shareID` plus storage scopes clamped to the share
// owner's current parent role. No session is available for that
// owner at mint time, so DB-recorded membership is the only
// authoritative signal we can consult.
func EffectiveCollectionRole(db *gorm.DB, coll *Collection, userID, username string) AclRole {
	if coll == nil {
		return ""
	}
	// No asserted group names: this path deliberately answers "what does
	// this user hold right now", independent of any session. Mirrored
	// memberships count even when stale — see
	// ResolveCallerACLSubjectsToleratingStale for why this one caller
	// tolerates that and no other does.
	subjects := ResolveCallerACLSubjectsToleratingStale(db, username, userID)

	// Direct ownership — Owner takes precedence over everything else.
	if subjects.UserID != "" && coll.OwnerID != "" && coll.OwnerID == subjects.UserID {
		return AclRoleOwner
	}
	// Admin-group membership — also Owner-equivalent for storage
	// purposes (the admin group can add/remove members and ACLs;
	// the only thing they can't do is delete the collection).
	if coll.AdminID != "" && slices.Contains(subjects.GroupIDs, coll.AdminID) {
		return AclRoleOwner
	}

	best := AclRole("")
	for _, acl := range coll.ACLs {
		if acl.ExpiresAt != nil && acl.ExpiresAt.Before(time.Now()) {
			continue
		}
		if !subjects.Matches(acl) {
			continue
		}
		if rolePriority(acl.Role) > rolePriority(best) {
			best = acl.Role
		}
	}
	return best
}

// CallerIsCollectionOwnerOrAdmin reports whether the caller's
// identity gives them owner-or-admin authority on the collection:
// their User.ID matches Collection.OwnerID, or they belong to
// Collection.AdminID (the admin group, by DB-recorded membership or by
// an asserted group name that resolves to it). When this returns true
// the caller skips the ACL check entirely — they have full management
// authority.
//
// There is deliberately no username path. Matching the caller's
// username against a username stored on the row is what let a
// previous owner keep authority after a PATCH transfer and let a
// reclaimed username inherit a deleted account's collections
// (issue #3753); the `owner` column backing it is gone.
//
// `db` may be nil during in-memory unit tests of the ACL filter; in
// that case only the caller-supplied User.ID is available, and the
// function still answers correctly for the owner case.
func CallerIsCollectionOwnerOrAdmin(db *gorm.DB, collection *Collection, username, userID string, groups []string) bool {
	return ResolveCallerACLSubjects(db, username, userID, groups).IsOwnerOrAdmin(collection)
}

// IsOwnerOrAdmin is CallerIsCollectionOwnerOrAdmin against an
// already-resolved subject set. Callers that check many collections for
// one caller — the listing endpoints, which compute a per-row `canEdit`
// — should resolve once and call this, rather than re-running the
// identity queries per row.
func (s CallerACLSubjects) IsOwnerOrAdmin(collection *Collection) bool {
	if collection == nil {
		return false
	}
	if s.UserID != "" && collection.OwnerID != "" && s.UserID == collection.OwnerID {
		return true
	}
	if collection.AdminID == "" {
		return false
	}
	return slices.Contains(s.GroupIDs, collection.AdminID)
}

// CallerIsCollectionOwner is the strict variant of
// CallerIsCollectionOwnerOrAdmin: it returns true ONLY when the caller
// is the actual owner of the collection (matched by User.ID slug or
// the legacy username). Admin-group members do NOT pass.
//
// Used to gate the dispose-of-the-collection operations — ownership
// transfer and deletion. Admin-group members can manage members, ACLs,
// metadata, and descriptive fields, but the design contract reserves
// "transfer or destroy" for the owner alone (otherwise an admin-group
// member could lock the actual owner out of their own collection by
// reassigning ownership to themselves or wiping the row).
//
// Privileged scopes (server.admin / server.collection_admin) are
// NOT consulted here — the caller is responsible for layering an
// admin-scope check on top when that bypass is appropriate (it is
// for the management API, but isn't a property of this helper).
//
// `db` may be nil, in which case only a caller who already carries a
// User.ID can match; a caller identified by username alone cannot be
// resolved without a query and is treated as a non-owner.
func CallerIsCollectionOwner(db *gorm.DB, collection *Collection, username, userID string) bool {
	if collection == nil || collection.OwnerID == "" {
		return false
	}
	if userID != "" {
		return userID == collection.OwnerID
	}
	if db == nil || username == "" {
		return false
	}
	var u User
	if err := db.Select("id").Where("username = ?", username).First(&u).Error; err != nil {
		return false
	}
	return u.ID == collection.OwnerID
}

// validateACL is the ownership + ACL access check used by every
// CRUD-walled collection function. It returns nil iff:
//
//  1. The caller is the collection's owner — their User.ID matches
//     Collection.OwnerID. Owner authority is unconditional (read +
//     write + delete + transfer).
//  2. The caller is a member of Collection.AdminID. Admin-group
//     authority covers everything except ownership transfer and
//     deletion — both of those re-gate to owner-exclusive in
//     UpdateCollection / DeleteCollection / the ownership-invite
//     mint path, so admin-group members pass this check but get
//     refused at the dispose-of-the-collection layer.
//  3. The caller has a non-expired ACL row whose role satisfies the
//     supplied scope.
//
// Every other case returns ErrForbidden. `db` may be nil only when
// the caller knows there is no admin group to consult (legacy unit
// tests); production code should always pass the live DB so the
// admin-group bypass works.
func validateACL(db *gorm.DB, collection *Collection, user, userID string, groups []string, scope token_scopes.TokenScope) error {
	// Resolve the caller once; both the ownership check and the ACL
	// scan below match against the same ID-keyed subject set. See
	// ResolveCallerACLSubjects for the contract.
	subjects := ResolveCallerACLSubjects(db, user, userID, groups)
	if subjects.IsOwnerOrAdmin(collection) {
		return nil
	}

	roles, ok := ScopeToRole[scope]
	if !ok {
		return fmt.Errorf("invalid scope: %s", scope.String())
	}

	for _, acl := range collection.ACLs {
		// Skip expired grants and keep scanning — a caller may hold the
		// required role through more than one subject, and ACL row order is
		// not deterministic. Returning ErrForbidden on the first expired
		// match (as this did previously) would intermittently deny a user
		// who also has a still-valid grant, purely based on iteration
		// order. This mirrors EffectiveCollectionRole, which likewise
		// `continue`s past expired rows.
		if acl.ExpiresAt != nil && acl.ExpiresAt.Before(time.Now()) {
			continue
		}
		if subjects.Matches(acl) && slices.Contains(roles, acl.Role) {
			return nil
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

	// User not found, create one.
	created, createErr := CreateUser(db, username, sub, issuer, creator)
	if createErr == nil {
		return created, nil
	}
	// A concurrent request may have created the same (sub, issuer) user between
	// our SELECT above and this INSERT, tripping a UNIQUE constraint. For a
	// get-or-create that is not a failure: if the row now exists, return it so
	// concurrent first-time authentications don't spuriously fail (a 500 on the
	// losing request). Re-fetch by the exact (sub, issuer) we were asked for, so
	// an unrelated username/issuer collision still surfaces the original error.
	if getErr := db.Where("sub = ? AND issuer = ?", sub, issuer).First(user).Error; getErr == nil {
		return user, nil
	}
	return nil, createErr
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
	// Stamp the operator-configured baseline scopes
	// (Server.NewUserDefaultScopes; default web_ui.access). Logged-only
	// on failure — the user record itself is the authoritative thing,
	// and the startup backfill is the safety net.
	ApplyDefaultUserScopes(db, newUser.ID, creator)
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
	ApplyDefaultUserScopes(db, user.ID, creator)
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
	ApplyDefaultUserScopes(db, user.ID, creator)
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
//
// `createdForCollectionID` ties the group to a specific collection's
// onboarding pass. Empty for the standalone group-create path; set by
// the collection-onboarding flow so a later ownership transfer of that
// collection can cascade to its onboarded groups (see
// RedeemCollectionOwnershipInviteLink).
//
// `authTemplateEligible` controls whether this group can match
// Issuer.AuthorizationTemplates and Server.*AdminGroups at runtime.
// The handler is responsible for refusing to set it true for a
// non-admin caller; this layer just persists what it's told.
func CreateGroup(db *gorm.DB, name, displayName, description string, creator Creator, createdForCollectionID string, authTemplateEligible bool) (*Group, error) {
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
	if strings.HasPrefix(name, PersonalACLGroupPrefix) {
		return nil, ErrReservedGroupPrefix
	}

	// A name an identity provider already asserts is off-limits:
	// EnsureAssertedGroups has minted an admin-owned record for it, and
	// letting a user take the name would let them stand in for the
	// provider's group in every ACL keyed on it. The unique index on
	// groups.name would reject this anyway; the explicit check exists so
	// the caller gets an explanation instead of a constraint violation.
	var clash Group
	if err := db.Select("id", "name", "source").Where("name = ?", name).First(&clash).Error; err == nil {
		if clash.Source.IsAsserted() {
			return nil, fmt.Errorf("%w: %q is asserted by the %s group source", ErrGroupNameConflict, name, clash.Source)
		}
		return nil, fmt.Errorf("a group named %q already exists", name)
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
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
		ID:                     slug,
		Name:                   name,
		DisplayName:            displayName,
		Description:            description,
		CreatedBy:              createdBy,
		CreatorAuthMethod:      creator.AuthMethod,
		CreatorAuthMethodID:    creator.AuthMethodID,
		OwnerID:                owner,
		CreatedForCollectionID: createdForCollectionID,
		AuthTemplateEligible:   authTemplateEligible,
		Source:                 GroupSourcePelican,
	}

	if result := db.Create(group); result.Error != nil {
		return nil, result.Error
	}

	return group, nil
}

// maxAssertedGroupNameLen bounds what we will write into groups.name
// from a provider's assertion. Generous compared to ValidateIdentifier's
// 64 (asserted names are hierarchical and can be long), but bounded so a
// malformed claim can't balloon the table.
const maxAssertedGroupNameLen = 255

// GroupAutoCreationEnabled reports whether this server records a group
// the first time a provider asserts its name. On by default; operators
// opt out with Issuer.DisableGroupAutoCreation.
func GroupAutoCreationEnabled() bool {
	return !param.Issuer_DisableGroupAutoCreation.GetBool()
}

// BuiltinAdminUser returns the built-in "admin" account — the user
// whose username is "admin" on the server's own issuer
// (Server.ExternalWebUrl). Returns (nil, nil) when the URL isn't
// configured yet or the row hasn't been bootstrapped, so callers can
// treat "no admin yet" as a soft condition rather than an error.
// See BootstrapAdminAndBackfillOwners, which creates the row.
func BuiltinAdminUser(db *gorm.DB) (*User, error) {
	externalURL := param.Server_ExternalWebUrl.GetString()
	if db == nil || externalURL == "" {
		return nil, nil
	}
	var admin User
	err := db.Where("username = ? AND issuer = ?", "admin", externalURL).First(&admin).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &admin, nil
}

// EnsureAssertedGroups records a `groups` row for every group name
// `source` asserted, so the name has a stable ID that collection ACLs
// and group scopes can key on.
//
// Why this exists. Group names used to come from two unreconciled
// places: records in this table, and whatever a provider asserted in a
// token. Because ACLs matched on the name, the two were
// indistinguishable at authorization time — so an unprivileged user
// could create a group named after one the provider asserts and step
// into its grants, and there was no ID to key an ACL on for a group
// that had never been created in Pelican. Recording the row on first
// observation collapses the two into one: from then on the provider's
// group has an ID, and CreateGroup refuses the name
// (ErrGroupNameConflict) because it is taken.
//
// The row is owned by the built-in admin user, not by whoever happened
// to log in, so no ordinary user inherits authority over it. Its
// membership is NOT written to `group_members`: the asserting provider
// stays the source of truth for who is in it, and
// ResolveCallerACLSubjects resolves a caller's asserted names to these
// IDs on every request.
//
// AuthTemplateEligible is set true AT CREATION, which preserves today's
// behavior rather than changing it: FilterAuthTemplateEligibleGroups
// passes through names it has no record for, so an asserted name already
// matches Issuer.AuthorizationTemplates / Server.*AdminGroups, and
// recording it with the bit clear would silently revoke that.
//
// Re-observation deliberately does NOT touch the bit. An admin who
// clears it has made a decision — often precisely because the name is
// attacker-influenced, e.g. a GitHub org anyone may register — and
// restoring it on the next login of any member would undo that
// decision silently and leave the operator no lever at all.
//
// A record that already exists with source GroupSourcePelican is left
// completely alone: a user-created group must never be promoted to
// template eligibility by an assertion.
//
// `source` must be the provider that actually asserted the names, and
// must be one an operator configured via Issuer.GroupSource. Do NOT feed
// this group names out of arbitrary federation bearer tokens: a foreign
// issuer could then reserve names on this server.
//
// Errors are returned but are not fatal to the caller's flow — a login
// should still succeed if the bookkeeping write fails; the names just
// stay unreconciled until the next observation.
func EnsureAssertedGroups(db *gorm.DB, source GroupSource, names []string) (accepted []string, err error) {
	if db == nil || len(names) == 0 || !GroupAutoCreationEnabled() {
		return nil, nil
	}
	if !source.IsAsserted() {
		return nil, fmt.Errorf("group source %q does not assert memberships", source)
	}

	wanted := recordableGroupNames(names, fmt.Sprintf("asserted by the %s source", source))
	if len(wanted) == 0 {
		return nil, nil
	}

	var existing []Group
	if err := db.Select("id", "name", "source", "auth_template_eligible").
		Where("name IN ? AND deleted_at IS NULL", wanted).Find(&existing).Error; err != nil {
		return nil, err
	}
	known := make(map[string]Group, len(existing))
	for _, g := range existing {
		known[g.Name] = g
	}

	accepted = make([]string, 0, len(wanted))
	var adminID, createdBy string
	if len(known) < len(wanted) {
		admin, err := BuiltinAdminUser(db)
		if err != nil {
			return nil, err
		}
		if admin != nil {
			adminID = admin.ID
			createdBy = admin.ID
		} else {
			// No admin row yet (brand-new install). Leave the group
			// ownerless; BootstrapAdminAndBackfillOwners assigns every
			// ownerless group to the admin on the next startup.
			createdBy = CreatorUnknown
		}
	}

	for _, name := range wanted {
		g, ok := known[name]
		if ok {
			if g.Source == GroupSourcePelican {
				log.Warnf("Group %q asserted by the %s source collides with a Pelican-created group (id %s); "+
					"the Pelican group is left alone and no membership will be mirrored into it", name, source, g.ID)
				continue
			}
			switch g.Source {
			case GroupSourceUnknown:
				// Completing a record the migration could only mark
				// unknown — not changing a source, recording the one it
				// always had.
				if err := db.Model(&Group{}).Where("id = ?", g.ID).
					Update("source", source).Error; err != nil {
					return nil, err
				}
			case source:
				// Nothing to do.
			default:
				// A group's source is a fact about where it came from,
				// set once at bootstrap, so an operator who switches
				// Issuer.GroupSource can still see which records predate
				// the switch. Re-stamping would erase exactly that.
				log.Warnf("Group %q was recorded from the %s source but is now asserted by %s; "+
					"leaving its recorded source alone", name, g.Source, source)
			}
			accepted = append(accepted, name)
			continue
		}
		slug, err := generateSlug()
		if err != nil {
			return nil, err
		}
		grp := &Group{
			ID:                   slug,
			Name:                 name,
			CreatedBy:            createdBy,
			OwnerID:              adminID,
			AuthTemplateEligible: true,
			Source:               source,
		}
		if err := db.Create(grp).Error; err != nil {
			// Another request observing the same assertion got there
			// first; that is a success for our purposes.
			if isUniqueConstraintError(err) {
				accepted = append(accepted, name)
				continue
			}
			return nil, err
		}
		accepted = append(accepted, name)
		log.Infof("Recorded group %q asserted by the %s source as group ID %s", name, source, slug)
	}
	return accepted, nil
}

// MirroredMembershipTTL is how long a mirrored membership may still
// grant access after the provider last asserted it
// (Issuer.AssertedGroupMembershipTTL). Zero disables mirrored
// memberships as an authorization input without disabling the mirror
// itself — the rows are still recorded and still shown in the UI.
func MirroredMembershipTTL() time.Duration {
	return param.Issuer_AssertedGroupMembershipTTL.GetDuration()
}

// freshAssertedMembershipCutoff returns the timestamp a mirrored row's
// asserted_at must beat to still grant, and whether mirrored rows may
// grant at all.
//
// Every GRANTING consumer must apply this; a RESTRICTING one
// ("might this account hold a privilege?") must not, because for those
// a stale copy still has to answer yes. That asymmetry is the whole
// reason freshness gates granting rather than retention — see the
// GroupMember.AssertedAt contract.
func freshAssertedMembershipCutoff() (time.Time, bool) {
	ttl := MirroredMembershipTTL()
	if ttl <= 0 {
		return time.Time{}, false
	}
	return time.Now().Add(-ttl), true
}

// membershipQuery builds the base query over a user's group
// memberships, joined to live groups only. `grantingOnly` selects
// between the two views the rest of this file is careful to keep
// apart: the granting view drops mirrored memberships whose last
// assertion is older than the TTL, while the restricting view keeps
// them.
func membershipQuery(db *gorm.DB, userID string, grantingOnly bool) *gorm.DB {
	q := db.Table("group_members").
		Joins("JOIN groups ON groups.id = group_members.group_id AND groups.deleted_at IS NULL").
		Where("group_members.user_id = ?", userID)
	if !grantingOnly {
		return q
	}
	if cutoff, mirroredMayGrant := freshAssertedMembershipCutoff(); mirroredMayGrant {
		return q.Where("group_members.source = ? OR group_members.asserted_at > ?", GroupSourcePelican, cutoff)
	}
	return q.Where("group_members.source = ?", GroupSourcePelican)
}

// grantingMembershipsFor returns the group IDs a user holds that may
// grant access right now: every Pelican-created membership, plus every
// mirrored membership the provider has asserted within the TTL.
func grantingMembershipsFor(db *gorm.DB, userID string) ([]string, error) {
	if db == nil || userID == "" {
		return nil, nil
	}
	var rows []struct{ GroupID string }
	if err := membershipQuery(db, userID, true).
		Select("group_members.group_id").Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.GroupID)
	}
	return out, nil
}

// groupNamesFor returns the names of the groups the user belongs to
// under one of the two membership views.
func groupNamesFor(db *gorm.DB, userID string, grantingOnly bool) ([]string, error) {
	if db == nil || userID == "" {
		return nil, nil
	}
	var rows []struct{ Name string }
	if err := membershipQuery(db, userID, grantingOnly).
		Select("groups.name").Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		if r.Name != "" {
			out = append(out, r.Name)
		}
	}
	return out, nil
}

// GroupNamesForGranting returns the names of every group the user
// belongs to that may confer authority right now — the name-space
// counterpart of grantingMembershipsFor.
//
// Use this wherever a true answer HANDS SOMETHING OUT. Its stale-
// tolerant twin, GroupNamesForRestrictionCheck, is for the questions
// where a true answer refuses something.
func GroupNamesForGranting(db *gorm.DB, userID string) ([]string, error) {
	return groupNamesFor(db, userID, true)
}

// GroupNamesForRestrictionCheck returns the names of every group the
// user belongs to, INCLUDING mirrored memberships that have gone stale.
//
// This is the deliberate counterpart to GroupNamesForGranting, and the
// two must not be confused. Use this only where the answer RESTRICTS
// what a caller may do — web_ui.MustTreatAsSystemAdmin, which stops a
// user-administrator from acting on a system administrator's account,
// is the motivating case. There, "we last saw this account in an admin
// group a month ago" must mean "refuse", not "go ahead": treating a
// stale copy as absence is what opens the guard.
//
// Never use it to decide whether to hand out access.
func GroupNamesForRestrictionCheck(db *gorm.DB, userID string) ([]string, error) {
	return groupNamesFor(db, userID, false)
}

// RecordGroupAdminObservation latches what an observation of a user's
// asserted group set concluded about their administrator privileges.
//
// `sawAdminGroup` is the caller's verdict — the group-to-scope matching
// lives in the web layer, which owns the Server.*AdminGroups config, so
// this function does not re-derive it. It only enforces the latch:
//
//   - true always sets GroupAdminPossible.
//   - false moves GroupAdminUnknown to GroupAdminRuledOut, and leaves
//     GroupAdminPossible alone. That asymmetry IS the latch: a provider
//     retracting an administrative membership removes the evidence, not
//     the history, and an account that has ever been able to administer
//     this server should not become manageable by a user-administrator
//     because the evidence went away.
//
// GroupsObservedAt is stamped either way, so an operator can tell "we
// looked and found nothing" from "we have never looked".
func RecordGroupAdminObservation(db *gorm.DB, userID string, sawAdminGroup bool) error {
	if db == nil || userID == "" {
		return nil
	}
	now := time.Now()
	updates := map[string]interface{}{"groups_observed_at": now}
	if sawAdminGroup {
		updates["group_admin_status"] = GroupAdminPossible
		return db.Model(&User{}).Where("id = ?", userID).Updates(updates).Error
	}
	// Never downgrade a latched account.
	updates["group_admin_status"] = GroupAdminRuledOut
	return db.Model(&User{}).
		Where("id = ? AND group_admin_status <> ?", userID, GroupAdminPossible).
		Updates(updates).Error
}

// MirrorAssertedGroupMemberships records, for one user, the memberships
// `source` just asserted, and drops the ones it no longer asserts.
//
// A Pelican-created membership is never touched: it is authoritative,
// so an admin who adds a local member to an asserted group keeps them.
//
// Everything else IS in scope, not just rows already stamped `source`.
// Issuer.GroupSource is single-valued, so at any moment exactly one
// provider decides membership, and a row left behind by a previous one
// is stale by definition. Retracting those here is what makes a change
// of Issuer.GroupSource take effect: without it the old provider's rows
// would linger, granting until their TTL expired, with nothing left to
// retract them. The group RECORDS keep their original source either way
// — that is a fact about where a group came from, and an operator can
// still see which ones predate the switch.
//
// `acceptedNames` must be what EnsureAssertedGroups accepted, not the
// raw assertion: a name it declined — one a Pelican-created group
// already holds — must not get a membership mirrored into that group,
// since nothing could then remove it.
//
// Passing an empty list is meaningful, not a no-op: it says the
// provider asserts nothing for this user, and retracts accordingly. A
// caller that merely FAILED to ask must not call this at all.
func MirrorAssertedGroupMemberships(db *gorm.DB, source GroupSource, userID string, acceptedNames []string) error {
	if db == nil || userID == "" || !GroupAutoCreationEnabled() {
		return nil
	}
	if !source.IsAsserted() {
		return fmt.Errorf("group source %q does not assert memberships", source)
	}

	// Resolve to the group records EnsureAssertedGroups accepted. The
	// `source <> pelican` filter is the second half of that agreement:
	// even if a caller passes a name it should not have, a membership
	// never lands in a group Pelican owns.
	assertedIDs := []string{}
	if len(acceptedNames) > 0 {
		var rows []struct{ ID string }
		if err := db.Table("groups").
			Select("id").
			Where("name IN ? AND deleted_at IS NULL AND source <> ?", acceptedNames, GroupSourcePelican).
			Scan(&rows).Error; err != nil {
			return err
		}
		for _, r := range rows {
			assertedIDs = append(assertedIDs, r.ID)
		}
	}

	now := time.Now()
	return db.Transaction(func(tx *gorm.DB) error {
		// Drop every mirrored membership this user has that the current
		// provider does not assert — including ones stamped by a
		// previous Issuer.GroupSource. Done before adding, so a
		// membership that moved between groups cannot briefly appear in
		// both.
		stale := tx.Where("user_id = ? AND source <> ?", userID, GroupSourcePelican)
		if len(assertedIDs) > 0 {
			stale = stale.Where("group_id NOT IN ?", assertedIDs)
		}
		if err := stale.Delete(&GroupMember{}).Error; err != nil {
			return err
		}
		if len(assertedIDs) == 0 {
			return nil
		}

		// Refresh or insert. A row that already exists as
		// GroupSourcePelican is left untouched: it outranks an
		// assertion, and stamping asserted_at on it would make an
		// administrator's deliberate membership expire.
		for _, groupID := range assertedIDs {
			member := GroupMember{
				GroupID:    groupID,
				UserID:     userID,
				AddedBy:    creatorOrUnknown(""),
				Source:     source,
				AssertedAt: &now,
			}
			// Refresh any mirrored row for this pair, whatever source it
			// carries, and restamp it to the current provider. Symmetric
			// with the retraction above: both treat "mirrored" as one
			// scope, so a provider change cannot leave a row that one
			// half owns and the other does not.
			res := tx.Model(&GroupMember{}).
				Where("group_id = ? AND user_id = ? AND source <> ?", groupID, userID, GroupSourcePelican).
				Updates(map[string]interface{}{"source": source, "asserted_at": now})
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected > 0 {
				continue
			}
			// No mirrored row to refresh: either there is none at all, or
			// there is a Pelican one we must not touch. DoNothing sorts
			// the two out without a second query.
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&member).Error; err != nil {
				return err
			}
		}
		return nil
	})
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
			// Membership of the admin group is a GRANTING decision, so
			// it goes through grantingMembershipsFor: a mirrored row the
			// provider stopped asserting is kept for restricting
			// questions, but it must not still confer authority over
			// this group.
			if ids, err := grantingMembershipsFor(db, userID); err == nil && slices.Contains(ids, group.AdminID) {
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
//
// `isUserAdminCaller` is the user-admin scope-bearer flag. The
// authTemplateEligible field can be flipped only by an admin or
// user-admin (a non-admin owner of the group cannot quietly grant
// their own group authz-template authority).
func UpdateGroup(db *gorm.DB, id string, name, displayName, description *string, authTemplateEligible *bool, requestorUserID string, isAdmin, isUserAdminCaller bool) error {
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
	if authTemplateEligible != nil {
		// Only a full system admin may set this bit — NOT a user_admin.
		// auth_template_eligible is the boundary that stops a group's
		// *name* from conferring authority: EffectiveScopesForIdentity
		// grants Server.AdminGroups-matched (or authz-template-matched)
		// scopes only to groups whose eligibility bit is set. If a
		// server.user_admin could flip it, they could self-escalate to
		// server.admin — take a group whose name coincides with a
		// Server.AdminGroups entry, own/administer it, set the bit, and
		// every member (themselves included) inherits server.admin, a
		// strictly higher privilege than the user_admin they hold. So
		// this must require the system-admin scope, not the user-admin
		// one. (The owner of a group still cannot set it on their own.)
		if !isAdmin {
			return ErrForbidden
		}
		updates["auth_template_eligible"] = *authTemplateEligible
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

		// An asserted group's name IS the link to the provider's
		// assertion — ResolveCallerACLSubjects matches the asserted name
		// against this column. Renaming it would silently detach every
		// member (their assertion no longer resolves) and the next login
		// would mint a second record under the original name. The
		// display name is still editable.
		if _, renaming := updates["name"]; renaming && group.Source.IsAsserted() {
			return fmt.Errorf("%w: %q is asserted by the %s group source and cannot be renamed",
				ErrGroupNameConflict, group.Name, group.Source)
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
		// Resolve the effective admin_type for validation: the incoming
		// value if provided, otherwise the group's current one. admin_id
		// and admin_type must stay consistent because the authorization
		// helpers (isGroupOwnerOrAdmin, ListGroupsVisibleToUser) branch on
		// admin_type and treat admin_id as either a User.ID or a Group.ID
		// accordingly. Writing an unvalidated admin_type would leave the
		// delegation silently non-matching; writing a dangling admin_id
		// would point authority at a non-existent principal.
		effectiveAdminType := group.AdminType
		if adminType != nil {
			if *adminType != AdminTypeUser && *adminType != AdminTypeGroup && *adminType != "" {
				return fmt.Errorf("invalid admin type %q: must be %q or %q", string(*adminType), AdminTypeUser, AdminTypeGroup)
			}
			effectiveAdminType = *adminType
			updates["admin_type"] = *adminType
		}
		if adminID != nil {
			// Verify the referenced admin principal exists, interpreting
			// admin_id per the effective admin_type. An empty admin_id
			// clears the delegation and needs no lookup.
			if *adminID != "" {
				switch effectiveAdminType {
				case AdminTypeUser:
					if err := tx.First(&User{}, "id = ?", *adminID).Error; err != nil {
						if errors.Is(err, gorm.ErrRecordNotFound) {
							return errors.New("admin user does not exist")
						}
						return err
					}
				case AdminTypeGroup:
					if err := tx.First(&Group{}, "id = ?", *adminID).Error; err != nil {
						if errors.Is(err, gorm.ErrRecordNotFound) {
							return errors.New("admin group does not exist")
						}
						return err
					}
				default:
					return errors.New("cannot set admin_id without a valid admin_type ('user' or 'group')")
				}
			}
			updates["admin_id"] = *adminID
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

	// Same contract as LeaveGroup: a mirrored membership belongs to the
	// provider. Removing the row here would look like it worked and be
	// undone at the member's next login, so say so instead. Note this
	// applies to admins too — the authority to manage a group does not
	// extend to overruling the identity provider.
	var member GroupMember
	err := db.Where("group_id = ? AND user_id = ?", groupId, userId).First(&member).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil // already not a member; removal is idempotent
		}
		return err
	}
	if member.IsMirrored() {
		return fmt.Errorf("%w: %q is asserted by the %s group source", ErrMembershipNotLocal, group.Name, member.Source)
	}

	if result := db.Where("group_id = ? AND user_id = ? AND source = ?", groupId, userId, GroupSourcePelican).
		Delete(&GroupMember{}); result.Error != nil {
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

// CollectionCandidateOwners returns the set of users who could
// plausibly be made the owner of the supplied collection — used to
// populate the owner-picker on the edit page WITHOUT having to expose
// the full users list to non-user-admin callers. The set is the
// union of:
//
//   - The current owner (so the picker can render "Display Name
//     (username)" for the current value, even if the caller has no
//     other relationship to the row).
//   - Members of the collection's admin group, if AdminID is set.
//   - Users named directly by a CollectionACL row, and members of
//     every group attached via one, regardless of read/write/owner
//     role.
//
// Returns UserCard rows so the caller never sees more than the
// public-safe (id, username, displayName) projection. Soft-deleted
// users are filtered out by GORM's default scope.
func CollectionCandidateOwners(db *gorm.DB, coll *Collection) ([]UserCard, error) {
	if coll == nil {
		return nil, errors.New("collection is required")
	}

	// Every handle involved is already an ID: group_members stores
	// user IDs, and an ACL row stores either a Group.ID or a User.ID.
	groupSlugs := []string{}
	if coll.AdminID != "" {
		groupSlugs = append(groupSlugs, coll.AdminID)
	}
	idSet := map[string]struct{}{}
	if coll.OwnerID != "" {
		idSet[coll.OwnerID] = struct{}{}
	}
	for _, a := range coll.ACLs {
		switch a.SubjectType {
		case ACLSubjectGroup:
			groupSlugs = append(groupSlugs, a.SubjectID)
		case ACLSubjectUser:
			idSet[a.SubjectID] = struct{}{}
		}
	}
	if len(groupSlugs) > 0 {
		var memberRows []struct {
			UserID string
		}
		if err := db.Table("group_members").
			Select("user_id").
			Where("group_id IN ?", groupSlugs).
			Scan(&memberRows).Error; err != nil {
			return nil, err
		}
		for _, r := range memberRows {
			if r.UserID != "" {
				idSet[r.UserID] = struct{}{}
			}
		}
	}

	if len(idSet) == 0 {
		return []UserCard{}, nil
	}
	ids := make([]string, 0, len(idSet))
	for id := range idSet {
		ids = append(ids, id)
	}
	cards, err := GetUserCards(db, ids)
	if err != nil {
		return nil, err
	}
	out := make([]UserCard, 0, len(cards))
	for _, c := range cards {
		out = append(out, c)
	}
	// Stable order: alphabetical by username — keeps the dropdown
	// predictable and the test fixtures deterministic.
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, nil
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
	// A mirrored membership is not ours to remove: the provider decides
	// it, and the next login would put it back. Refusing is the honest
	// answer — the user has to be removed at the provider.
	var member GroupMember
	if err := db.Where("group_id = ? AND user_id = ?", groupID, userID).First(&member).Error; err != nil {
		return err
	}
	if member.IsMirrored() {
		return fmt.Errorf("%w: %q is asserted by the %s group source", ErrMembershipNotLocal, group.Name, member.Source)
	}
	res := db.Where("group_id = ? AND user_id = ? AND source = ?", groupID, userID, GroupSourcePelican).
		Delete(&GroupMember{})
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

// DeleteGroup soft-deletes a group and clears everything that would
// otherwise keep pointing at it: collection ACL grants, group scopes,
// memberships, invite links, and any collection or group that named it
// as their administrator.
//
// Two rules are doing the work here. First, every reference keys on the
// group's ID, so the cleanup is a straight delete rather than the old
// "match whatever name the group happens to have right now" — which
// missed rows orphaned by an earlier rename (issue #3752). Second, the
// delete is SOFT, so the ID is spent forever; a hard delete freed it
// for a later group to be minted with (generateSlug is 8 hex characters
// with no uniqueness check) and inherit anything this cleanup missed.
// Belt and braces: the cleanup is exhaustive AND the ID cannot come
// back.
//
// Clearing admin_id rather than leaving it dangling matters for the
// collection case in particular: the collection would otherwise be
// stuck naming an administrator that no longer exists, which no UI
// surfaces and no caller can satisfy.
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

		// Remove any ACL entries referencing the group.
		if err := tx.Where("subject_type = ? AND subject_id = ?", ACLSubjectGroup, group.ID).
			Delete(&CollectionACL{}).Error; err != nil {
			return err
		}

		// Remove any scopes granted to the group. Without this the rows
		// survive the group and are inherited wholesale by anything
		// that later ends up holding the same ID.
		if err := tx.Where("group_id = ?", group.ID).Delete(&GroupScope{}).Error; err != nil {
			return err
		}

		// Stand the group down as administrator of any collection or
		// other group that named it.
		if err := tx.Model(&Collection{}).Where("admin_id = ?", group.ID).
			Update("admin_id", "").Error; err != nil {
			return err
		}
		if err := tx.Model(&Group{}).
			Where("admin_type = ? AND admin_id = ?", AdminTypeGroup, group.ID).
			Updates(map[string]interface{}{"admin_id": "", "admin_type": ""}).Error; err != nil {
			return err
		}

		// Delete group members explicitly (in addition to any FK cascade).
		if err := tx.Where("group_id = ?", group.ID).Delete(&GroupMember{}).Error; err != nil {
			return err
		}

		// Finally, tombstone the group itself. GORM turns this into an
		// UPDATE of deleted_at because Group carries a gorm.DeletedAt.
		if err := tx.Delete(&group).Error; err != nil {
			return err
		}

		return nil
	})
}

// DeleteUser deletes a user and cleans up any collection ACL entries
// granted to them personally. Like DeleteGroup this keys on the ID, so
// renames can't leave a grant behind.
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

		// Remove any ACL entries granted to this user personally.
		if err := tx.Where("subject_type = ? AND subject_id = ?", ACLSubjectUser, user.ID).
			Delete(&CollectionACL{}).Error; err != nil {
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

// CreateCollectionOwnershipInviteLink mints a single-use invite that,
// when redeemed by a logged-in user, transfers Collection.OwnerID from
// the current owner to the redeemer. The previous owner stays referenced via
// CreatedBy on the invite + audit fields on the collection row, but
// loses ownership the moment the link is redeemed.
//
// Authorization: the caller must already be able to mutate the
// collection — owner, admin-group member, or holder of
// server.collection_admin / server.admin (the same gate as
// `PATCH /:id` with ownerId / adminId). We derive the result of
// that gate from `isCollectionAdmin` (the scope-bypass) plus the
// owner / admin-group check inside the existing helper, mirroring
// how UpdateCollection re-gates ownership transfers.
//
// Single-use is forced — ownership transfer is by definition a
// one-shot operation; a multi-use ownership invite would be a
// security footgun.
func CreateCollectionOwnershipInviteLink(db *gorm.DB, collectionID, createdByUsername, createdByUserID string, callerGroups []string, expiresAt time.Time, isCollectionAdmin bool, authMethod AuthMethod, authMethodID string) (*GroupInviteLink, string, error) {
	if collectionID == "" {
		return nil, "", errors.New("collectionID is required")
	}
	collection := &Collection{}
	if err := db.Preload("ACLs").Where("id = ?", collectionID).First(collection).Error; err != nil {
		return nil, "", err
	}
	// Same gate as UpdateCollection's ownerID transfer: ONLY the
	// existing owner (or the scope-admin bypass) may mint an
	// ownership-transfer invite. Admin-group members can manage
	// members and ACLs, but handing out an ownership invite is
	// morally identical to transferring ownership; per the design
	// contract that's owner-exclusive.
	if !isCollectionAdmin && !CallerIsCollectionOwner(db, collection, createdByUsername, createdByUserID) {
		return nil, "", ErrForbidden
	}
	link, plaintext, err := mintInviteLink(db, GroupInviteLink{
		Kind:         InviteKindCollectionOwnership,
		CollectionID: collectionID,
		CreatedBy:    createdByUserID,
		AuthMethod:   authMethod,
		AuthMethodID: authMethodID,
		ExpiresAt:    expiresAt,
		IsSingleUse:  true,
	})
	if err != nil {
		return nil, "", err
	}
	return link, plaintext, nil
}

// RedeemCollectionOwnershipInviteLink consumes a plaintext ownership
// invite and transfers the collection's owner fields to the redeemer.
// The redeemer must be an authenticated user (we record their User.ID
// as the new owner); the link is marked redeemed in the same
// transaction so subsequent redemption attempts fail.
//
// Returns (collectionID, previousOwnerID, error). The collectionID
// lets the redemption page redirect to the now-owned collection;
// previousOwnerID is informational (audit log).
func RedeemCollectionOwnershipInviteLink(db *gorm.DB, plaintext string, redeemerUserID string) (string, string, error) {
	if redeemerUserID == "" {
		return "", "", errors.New("redeemer user ID is required")
	}
	var collectionID, previousOwnerID string
	err := db.Transaction(func(tx *gorm.DB) error {
		var links []GroupInviteLink
		if err := tx.Where("revoked = 0 AND expires_at > ? AND kind = ?", time.Now(), InviteKindCollectionOwnership).Find(&links).Error; err != nil {
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
		// Single-use is the only supported mode, but check defensively
		// in case a future schema relaxes that constraint.
		if link.IsSingleUse && link.RedeemedBy != "" {
			return errors.New("invite link has already been redeemed")
		}
		// Look up the collection (must still exist) and the redeemer
		// (must be a real, active user).
		var collection Collection
		if err := tx.First(&collection, "id = ?", link.CollectionID).Error; err != nil {
			return err
		}
		var redeemer User
		if err := tx.First(&redeemer, "id = ?", redeemerUserID).Error; err != nil {
			return err
		}
		if redeemer.Status != UserStatusActive {
			return errors.New("redeemer's account is not active")
		}
		previousOwnerID = collection.OwnerID
		collectionID = collection.ID

		// Claim the link FIRST with a race-safe conditional update —
		// the same guard the group and password redeem paths use. The
		// in-memory `RedeemedBy != ""` check above is not sufficient on
		// its own: two concurrent redemptions can both read the link as
		// unredeemed and both proceed, each performing the (last-writer-
		// wins) ownership transfer. Marking redeemed_by only where it is
		// still '' and aborting when no row is affected makes the
		// single-use invariant hold under concurrency. We do it before
		// the transfer so a losing racer never touches owner_id.
		now := time.Now()
		claim := tx.Model(&GroupInviteLink{}).
			Where("id = ? AND redeemed_by = ''", link.ID).
			Updates(map[string]interface{}{
				"redeemed_by": redeemer.ID,
				"redeemed_at": &now,
			})
		if claim.Error != nil {
			return claim.Error
		}
		if claim.RowsAffected == 0 {
			return errors.New("invite link has already been redeemed")
		}

		// owner_id is the whole of ownership; there is no second
		// username column to keep in lockstep any more, which is what
		// made the PATCH path (which only ever wrote owner_id) a
		// privilege-retention bug before.
		if err := tx.Model(&Collection{}).
			Where("id = ?", link.CollectionID).
			Update("owner_id", redeemer.ID).Error; err != nil {
			return err
		}

		// Cascade: every group that was minted alongside this
		// collection during onboarding follows the collection on
		// transfer (per the demo punch-list #2C). The "AND owner_id =
		// previous owner" clause prevents stomping on a group whose
		// ownership was already re-homed manually since onboarding;
		// without that guard a stray ownership transfer would yank
		// groups away from whoever was administering them.
		//
		// previousOwnerID may be empty for legacy collections that
		// never had owner_id populated. In that case we skip the
		// cascade entirely — there's no safe predicate to identify
		// "still owned by the original onboarding owner."
		if previousOwnerID != "" {
			if err := tx.Model(&Group{}).
				Where("created_for_collection_id = ? AND owner_id = ?", link.CollectionID, previousOwnerID).
				Update("owner_id", redeemer.ID).Error; err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return "", "", err
	}
	return collectionID, previousOwnerID, nil
}

// CreateRegistrationOwnershipInviteLink mints a single-use invite that,
// when redeemed by an authenticated user, transfers ownership of the
// registry registration to that user. Unlike the collection variant,
// the ownership gate (only the registration's current owner or a
// registry admin may mint) is enforced by the caller: the registration
// permission model lives in the registry package, which is the only
// caller of this helper.
//
// Single-use is forced — ownership transfer is by definition a
// one-shot operation.
func CreateRegistrationOwnershipInviteLink(db *gorm.DB, registrationID int, createdByUserID string, expiresAt time.Time, authMethod AuthMethod, authMethodID string) (*GroupInviteLink, string, error) {
	if registrationID <= 0 {
		return nil, "", errors.New("registrationID is required")
	}
	return mintInviteLink(db, GroupInviteLink{
		Kind:           InviteKindRegistrationOwnership,
		RegistrationID: registrationID,
		CreatedBy:      createdByUserID,
		AuthMethod:     authMethod,
		AuthMethodID:   authMethodID,
		ExpiresAt:      expiresAt,
		IsSingleUse:    true,
	})
}

// RedeemRegistrationOwnershipInviteLink consumes a plaintext ownership
// invite and records the redeemer's Pelican User.ID as the owner of the
// registry registration. The link is marked redeemed in the same
// transaction so subsequent redemption attempts fail.
//
// Returns (registrationID, registrationPrefix, error); the prefix lets
// the redemption page tell the user what they now own.
func RedeemRegistrationOwnershipInviteLink(db *gorm.DB, plaintext string, redeemerUserID string) (int, string, error) {
	if redeemerUserID == "" {
		return 0, "", errors.New("redeemer user ID is required")
	}
	var registrationID int
	var registrationPrefix string
	err := db.Transaction(func(tx *gorm.DB) error {
		var links []GroupInviteLink
		if err := tx.Where("revoked = 0 AND expires_at > ? AND kind = ?", time.Now(), InviteKindRegistrationOwnership).Find(&links).Error; err != nil {
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
		// Single-use is the only supported mode, but check defensively
		// in case a future schema relaxes that constraint.
		if link.IsSingleUse && link.RedeemedBy != "" {
			return errors.New("invite link has already been redeemed")
		}
		// The registration must still exist and the redeemer must be a
		// real, active user.
		var reg server_structs.Registration
		if err := tx.First(&reg, "id = ?", link.RegistrationID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("the registration (ID %d) this invite refers to no longer exists", link.RegistrationID)
			}
			return err
		}
		var redeemer User
		if err := tx.First(&redeemer, "id = ?", redeemerUserID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("redeemer user %q does not exist", redeemerUserID)
			}
			return err
		}
		if redeemer.Status != UserStatusActive {
			return errors.New("redeemer's account is not active")
		}
		registrationID = reg.ID
		registrationPrefix = reg.Prefix

		// Claim the link FIRST with a race-safe conditional update, the
		// same guard the other redeem paths use, so two concurrent
		// redemptions can't both perform the transfer.
		now := time.Now()
		claim := tx.Model(&GroupInviteLink{}).
			Where("id = ? AND redeemed_by = ''", link.ID).
			Updates(map[string]interface{}{
				"redeemed_by": redeemer.ID,
				"redeemed_at": &now,
			})
		if claim.Error != nil {
			return claim.Error
		}
		if claim.RowsAffected == 0 {
			return errors.New("invite link has already been redeemed")
		}

		// The link is consumed; hand the registration to the redeemer.
		return SetRegistrationOwner(tx, &reg, redeemer.ID)
	})
	if err != nil {
		return 0, "", err
	}
	return registrationID, registrationPrefix, nil
}

// SetRegistrationOwner is the single primitive through which a registration's
// owner (admin_metadata.user_id, a Pelican user ID) is written to the database.
// Every ownership change (a key-holder claim, or an ownership-transfer invite
// redemption) goes through it so the two side effects that must stay in
// lockstep cannot drift apart:
//
//  1. the owner is rewritten inside the JSON-serialized admin metadata
//     (read-modify-write, so reg must have been loaded within tx), and
//  2. every outstanding ownership-transfer invite for the registration is
//     revoked, because it was minted under an authority (the previous owner,
//     or an admin acting on an unowned row) that the change just ended.
//
// Callers own their preconditions (an unowned row for a claim, a valid
// single-use link for a redemption) and must run inside the transaction
// that read reg. reg is updated in place to mirror the write.
func SetRegistrationOwner(tx *gorm.DB, reg *server_structs.Registration, owner string) error {
	if owner == "" {
		return errors.New("registration owner must not be empty")
	}
	if reg == nil || reg.ID <= 0 {
		return errors.New("registration must be loaded before its owner can be set")
	}
	reg.AdminMetadata.UserID = owner
	reg.AdminMetadata.UpdatedAt = time.Now()
	adminMetadataBytes, err := json.Marshal(reg.AdminMetadata)
	if err != nil {
		return fmt.Errorf("failed to marshal admin metadata: %w", err)
	}
	if err := tx.Model(&server_structs.Registration{}).
		Where("id = ?", reg.ID).
		Update("admin_metadata", string(adminMetadataBytes)).Error; err != nil {
		return err
	}
	return RevokeRegistrationOwnershipInviteLinks(tx, reg.ID)
}

// RevokeRegistrationOwnershipInviteLinks revokes every outstanding
// (unredeemed, unrevoked) ownership-transfer invite for the given
// registration. SetRegistrationOwner calls it on every owner change so links
// minted under the previous owner's authority cannot transfer the
// registration out from under the new owner; call it directly only when
// invites must die without the owner changing. Accepts a transaction so the
// revocation is atomic with the owner write.
func RevokeRegistrationOwnershipInviteLinks(db *gorm.DB, registrationID int) error {
	return db.Model(&GroupInviteLink{}).
		Where("kind = ? AND registration_id = ? AND redeemed_by = '' AND revoked = 0",
			InviteKindRegistrationOwnership, registrationID).
		Update("revoked", true).Error
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
