//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"

	"github.com/pelicanplatform/pelican/param"
)

func doReload() error {
	db := authDB.Load()
	if db == nil {
		log.Debug("Cannot reload auth database - not configured")
		return nil
	}
	fileName := param.Server_UIPasswordFile.GetString()
	fp, err := os.OpenFile(fileName, os.O_RDONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Warning("Failed to open auth database for reload:", err)
		return err
	}
	defer fp.Close()
	if err = syscall.Flock(int(fp.Fd()), syscall.LOCK_SH); err != nil {
		log.Warning("Failed to lock the auth database for read:", err)
		return err
	}
	defer func() {
		if err := syscall.Flock(int(fp.Fd()), syscall.LOCK_UN); err != nil {
			log.Warning("Failed to unlock the auth database:", err)
		}
	}()

	err = db.Reload(nil)
	if err != nil {
		log.Warningln("Failed to reload auth database:", err)
		return err
	}
	log.Debug("Successfully reloaded the auth database")
	return nil
}

func writePasswordEntryImpl(user, password string) error {
	fileName := param.Server_UIPasswordFile.GetString()
	passwordBytes := []byte(password)
	if len(passwordBytes) > 72 {
		return errors.New("Password too long")
	}
	hashed, err := bcrypt.GenerateFromPassword(passwordBytes, bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	directory := filepath.Dir(fileName)
	err = os.MkdirAll(directory, 0750)
	if err != nil {
		return err
	}
	fp, err := os.OpenFile(fileName, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer fp.Close()

	if _, err := fp.Seek(0, 0); err != nil {
		log.Warning("Failed to seek to the beginning of the auth database:", err)
		return err
	}

	if err = syscall.Flock(int(fp.Fd()), syscall.LOCK_EX); err != nil {
		log.Warning("Failed to lock the auth database for read:", err)
		return err
	}
	defer func() {
		if err := syscall.Flock(int(fp.Fd()), syscall.LOCK_UN); err != nil {
			log.Warning("Failed to unlock the auth database:", err)
		}
	}()

	credentials := make(map[string]string)
	scanner := bufio.NewScanner(fp)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		info := strings.SplitN(scanner.Text(), ":", 2)
		if len(info) == 1 {
			log.Warning("Invalid line in the authdb file:", scanner.Text())
			continue
		}
		credentials[info[0]] = info[1]
	}
	credentials[user] = string(hashed)

	fp2, err := os.OpenFile(fileName, os.O_RDWR|os.O_TRUNC|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer fp2.Close()

	for user, pass := range credentials {
		entry := fmt.Sprintf("%s:%s\n", user, pass)
		if _, err = fp2.Write([]byte(entry)); err != nil {
			return err
		}
	}

	return nil
}

func WritePasswordEntry(user, password string) error {
	if err := writePasswordEntryImpl(user, password); err != nil {
		return err
	}

	db := authDB.Load()
	if db != nil {
		if err := db.Reload(nil); err != nil {
			return err
		}
	}
	return nil
}
