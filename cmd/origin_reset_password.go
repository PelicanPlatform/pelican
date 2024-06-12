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

package main

import (
	"fmt"
	"io"
	"syscall"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/pelicanplatform/pelican/web_ui"
)

func uiPasswordReset(cmd *cobra.Command, args []string) error {
	username, err := cmd.Flags().GetString("user")
	if err != nil {
		return errors.Wrapf(err, "Failed to get value of the --user flag")
	}
	if username == "" {
		return errors.New("Username must be a non-empty string")
	}

	stdin, err := cmd.Flags().GetBool("stdin")
	if err != nil {
		return errors.Wrapf(err, "Failed to get value of the --stdin flag")
	}

	var bytePassword []byte
	if stdin {
		bytePassword, err = io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return errors.Wrap(err, "Failed to read new password from stdin")
		}
	} else {
		fmt.Print("Enter new password: ")
		bytePassword, err = term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return errors.Wrap(err, "Failed to read new password from console")
		}
	}

	if err = web_ui.WritePasswordEntry(username, string(bytePassword)); err != nil {
		return errors.Wrapf(err, "Failed to update the password entry for user %s", username)
	}

	return nil
}
