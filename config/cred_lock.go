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

package config

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/gofrs/flock"
	log "github.com/sirupsen/logrus"
)

// credFileMu serializes credential-file read-modify-write cycles between
// goroutines of this process. The cross-process advisory file lock below
// complements it for other Pelican processes sharing the same wallet.
var credFileMu sync.Mutex

// WithCredentialFileLock runs fn while holding an exclusive lock on the
// credential file, so a read-modify-write cycle (read the wallet, change it,
// write it back) cannot interleave with another such cycle. Serialization is
// provided by an in-process mutex plus a best-effort advisory file lock for
// other processes.
//
// If the advisory file lock cannot be acquired (e.g. the platform or
// filesystem does not support it), fn still runs under the in-process mutex —
// callers must additionally write atomically, which SaveConfigContents does
// via a temp-file-and-rename. Hold the lock only around the read-modify-write,
// not around network calls.
func WithCredentialFileLock(fn func() error) error {
	credFileMu.Lock()
	defer credFileMu.Unlock()

	lockPath, err := credentialLockPath()
	if err != nil {
		log.Debugln("Credential file lock unavailable; proceeding optimistically:", err)
		return fn()
	}
	fl := flock.New(lockPath)
	if lockErr := fl.Lock(); lockErr != nil {
		log.Debugln("Failed to acquire credential file lock; proceeding optimistically:", lockErr)
		return fn()
	}
	defer func() {
		if unlockErr := fl.Unlock(); unlockErr != nil {
			log.Debugln("Failed to release credential file lock:", unlockErr)
		}
	}()
	return fn()
}

// credentialLockPath returns the path of the lock file guarding the credential
// file, ensuring its parent directory exists.
func credentialLockPath() (string, error) {
	name, err := GetEncryptedConfigName()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		return "", err
	}
	return name + ".lock", nil
}

// UpsertPrefixEntry atomically replaces (or appends) the OAuth client entry for
// the given federation discovery URL and prefix, holding the credential file
// lock and re-reading the wallet first so concurrent changes to other prefixes
// are preserved. The entry is matched by its Prefix field.
func UpsertPrefixEntry(discoveryURL string, entry *PrefixEntry) error {
	return WithCredentialFileLock(func() error {
		cfg, err := GetCredentialConfigContents()
		if err != nil {
			return err
		}
		fc := cfg.EnsureFederationCredentials(discoveryURL)
		replaced := false
		for i := range fc.OauthClient {
			if fc.OauthClient[i].Prefix == entry.Prefix {
				fc.OauthClient[i] = *entry
				replaced = true
				break
			}
		}
		if !replaced {
			fc.OauthClient = append(fc.OauthClient, *entry)
		}
		return SaveConfigContents(&cfg)
	})
}
