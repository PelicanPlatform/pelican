//go:build server && !windows

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

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/tg123/go-htpasswd"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/web_ui"
)

func getPassword() ([]byte, error) {
	passwords, err := config.ReadPasswordsFromTerminal("Enter your password:", "Confirm the password:")
	if err != nil {
		return nil, err
	}
	if string(passwords[0]) != string(passwords[1]) {
		return nil, errors.New("passwords do not match")
	}
	return passwords[1], nil
}

func passwordMain(cmd *cobra.Command, args []string) error {
	password := ""
	// password provided via --password flag
	if inPasswordPath != "" {
		inPasswordfile, err := os.Open(inPasswordPath)
		if err != nil {
			return err
		}
		defer inPasswordfile.Close()
		bytes, err := io.ReadAll(inPasswordfile)
		if err != nil {
			return err
		}
		password = strings.TrimSpace(string(bytes))
	} else {
		// read password from stdin
		pwdBytes, err := getPassword()
		if err != nil {
			return err
		}
		password = string(pwdBytes)
	}

	if password == "" {
		return errors.New("password is required")
	}

	wd, err := os.Getwd()
	if err != nil {
		return errors.Wrap(err, "failed to get the current working directory")
	}
	if outPasswordPath == "" {
		outPasswordPath = filepath.Join(wd, "server-web-passwd")
	} else {
		outPasswordPath = filepath.Clean(strings.TrimSpace(outPasswordPath))
	}

	if err = os.MkdirAll(filepath.Dir(outPasswordPath), 0755); err != nil {
		return errors.Wrapf(err, "failed to create directory for the password file at %s", filepath.Dir(outPasswordPath))
	}

	if err := param.Server_UIPasswordFile.Set(outPasswordPath); err != nil {
		return err
	}
	file, err := os.OpenFile(outPasswordPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	file.Close()

	// chown the file to the pelican user
	user, err := config.GetPelicanUser()
	if err != nil {
		return errors.Wrap(err, "no OS user found for pelican")
	}
	if err := os.Chown(outPasswordPath, user.Uid, user.Gid); err != nil {
		return errors.Wrapf(err, "failed to set ownership on %s", outPasswordPath)
	}

	_, err = htpasswd.New(outPasswordPath, []htpasswd.PasswdParser{htpasswd.AcceptBcrypt}, nil)
	if err != nil {
		return err
	}
	err = web_ui.WritePasswordEntry("admin", password)
	if err != nil {
		return errors.Wrap(err, "failed to write password to the file")
	}
	fmt.Printf("Successfully generated the admin password file at: %s\n", outPasswordPath)
	return nil
}
