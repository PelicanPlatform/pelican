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

package database

import (
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/param"
)

// InternalIssuer names the issuer of identities this server authenticates
// itself — an htpasswd entry or a password stored in `user_credentials`.
//
// It is a constant, not Server.ExternalWebUrl. The URL was never anything but
// a stand-in for "this server": it appears in no token, is never dereferenced,
// and nothing compares it to a token's `iss`. But an operator may change it —
// moving to a new hostname, binding a different port, or (in a test harness)
// letting the kernel pick one — and every account whose identity was written
// under the old value then became unreachable, which is how a server could
// lock its own administrator out (#3824). A constant cannot drift.
//
// The value is a URN so that it can never collide with an OIDC issuer, which
// is always an https URL.
const InternalIssuer = "urn:pelican:internal"

// adoptInternalIssuer moves identities written under this server's own URL,
// back when that URL *was* the internal issuer, onto InternalIssuer.
//
// Both candidate URLs are exact, not guesses: Server.ExternalWebUrl is what
// this server calls itself right now, and the built-in admin's own identity
// records whatever it called itself when that row was last written — which is
// the older value when the operator has since changed the URL. An OIDC
// provider cannot be served at either, so nothing external is swept up.
//
// TODO: remove once every supported upgrade path has passed through a release
// that contains it (see also prepareForGlobalUniqueUsernames).
func adoptInternalIssuer(db *gorm.DB) error {
	candidates := map[string]struct{}{}
	if url := param.Server_ExternalWebUrl.GetString(); url != "" {
		candidates[url] = struct{}{}
	}

	var adminIdentity UserIdentity
	err := db.Model(&UserIdentity{}).
		Joins("JOIN users ON users.id = user_identities.user_id AND users.deleted_at IS NULL").
		Where("users.username = ? AND user_identities.sub = ?", builtinAdminUsername, builtinAdminUsername).
		First(&adminIdentity).Error
	if err == nil {
		if adminIdentity.Issuer != InternalIssuer {
			candidates[adminIdentity.Issuer] = struct{}{}
		}
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return errors.Wrap(err, "failed to read the built-in admin's identity")
	}

	for issuer := range candidates {
		// An account that already holds an internal identity would collide on
		// the one-identity-per-issuer index. That can only happen when the URL
		// has changed more than once since the upgrade, leaving a stale row
		// behind; the internal identity it already has is the live one, so the
		// stale row is reported rather than forced through.
		res := db.Model(&UserIdentity{}).
			Where("issuer = ?", issuer).
			Where("NOT EXISTS (SELECT 1 FROM user_identities other WHERE other.user_id = user_identities.user_id AND other.issuer = ?)", InternalIssuer).
			Update("issuer", InternalIssuer)
		if res.Error != nil {
			return errors.Wrapf(res.Error, "failed to move identities at %q onto the internal issuer", issuer)
		}
		if res.RowsAffected > 0 {
			log.Infof("Moved %d local identity(ies) from %q to the internal issuer %q", res.RowsAffected, issuer, InternalIssuer)
		}
		var stranded int64
		if err := db.Model(&UserIdentity{}).Where("issuer = ?", issuer).Count(&stranded).Error; err != nil {
			return errors.Wrapf(err, "failed to count the identities left at %q", issuer)
		}
		if stranded > 0 {
			log.Warnf("%d identity(ies) remain at %q because their account already holds an internal identity; "+
				"an administrator can unlink them", stranded, issuer)
		}
	}
	return nil
}
