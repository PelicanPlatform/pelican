/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/client_api/apiclient"
)

var (
	jobCancelCmd = &cobra.Command{
		Use:   "cancel <job-id>",
		Short: "Cancel a transfer job",
		Long: `Cancel a transfer job and all its incomplete transfers.
Completed transfers within the job are not affected.`,
		Args: cobra.ExactArgs(1),
		RunE: jobCancelMain,
	}
)

func init() {
	jobCmd.AddCommand(jobCancelCmd)
}

func jobCancelMain(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	jobID := args[0]

	// Create API client
	apiClient, err := apiclient.NewAPIClient("")
	if err != nil {
		return errors.Wrap(err, "failed to create API client")
	}

	// Check if server is running
	if !apiClient.IsServerRunning(ctx) {
		return errors.New("API server is not running. Start it with: pelican client-api serve")
	}

	// Cancel job
	err = apiClient.CancelJob(ctx, jobID)
	if err != nil {
		return errors.Wrap(err, "failed to cancel job")
	}

	fmt.Printf("Job %s has been cancelled\n", jobID)
	return nil
}
