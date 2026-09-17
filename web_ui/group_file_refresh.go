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

package web_ui

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
)

// LaunchPeriodicGroupFileRefresh re-reads Issuer.GroupFile on an
// interval and refreshes the group memberships mirrored from it.
//
// This exists because `file` is the only group source Pelican can
// consult without the user present: it is a local file keyed by
// username, so membership for every known account can be recomputed at
// any time. `oidc` and `github` need that user's own token, so their
// mirrored memberships are only ever as fresh as the user's last login
// — which is exactly what Issuer.AssertedGroupMembershipTTL exists to
// bound. Refreshing the file source keeps it out of that bind
// altogether: its memberships stay continuously fresh, and an operator
// removing someone from the file sees it take effect within one
// interval rather than at that person's next login.
//
// A pass is a no-op when the file is unset, and errors are logged
// rather than returned — a malformed group file must not take the
// server down, and the next pass will pick up a corrected one.
func LaunchPeriodicGroupFileRefresh(ctx context.Context, egrp *errgroup.Group) {
	interval := param.Issuer_GroupFileRefreshInterval.GetDuration()
	if interval <= 0 {
		log.Debug("Periodic group-file refresh is disabled (Issuer.GroupFileRefreshInterval is 0)")
		return
	}
	if param.Issuer_GroupFile.GetString() == "" {
		log.Debug("Periodic group-file refresh is disabled (Issuer.GroupFile is unset)")
		return
	}

	egrp.Go(func() error {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		// One pass at startup so a server that has been down across a
		// group-file edit does not serve stale memberships until the
		// first tick.
		refreshGroupFileMemberships()
		for {
			select {
			case <-ticker.C:
				refreshGroupFileMemberships()
			case <-ctx.Done():
				log.Debug("Periodic group-file refresh has shut down")
				return nil
			}
		}
	})
}

// refreshGroupFileMemberships re-mirrors file-derived memberships for
// every user Pelican knows about.
//
// It walks users rather than the file's own keys deliberately: a file
// entry for a username with no account is not something to act on (there
// is no user to attach a membership to), while an account that has been
// REMOVED from the file must have its mirrored memberships retracted —
// and that only happens if we ask about the account. Passing an empty
// group list for such a user is the retraction.
func refreshGroupFileMemberships() {
	if database.ServerDatabase == nil {
		return
	}
	users, err := database.ListUsers(database.ServerDatabase)
	if err != nil {
		log.Warnf("Failed to list users for the periodic group-file refresh: %v", err)
		return
	}
	refreshed := 0
	for _, user := range users {
		groups, err := generateGroupInfo(user.Username)
		if err != nil {
			// A read or parse failure is about the file, not this user;
			// one complaint is enough.
			log.Warnf("Periodic group-file refresh aborted: %v", err)
			return
		}
		RecordAssertedGroups(database.GroupSourceFile, user.ID, user.Username, groups)
		refreshed++
	}
	log.Debugf("Periodic group-file refresh reconciled memberships for %d user(s)", refreshed)
}
