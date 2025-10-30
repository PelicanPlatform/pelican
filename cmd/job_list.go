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
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/client_api/apiclient"
)

var (
	jobListCmd = &cobra.Command{
		Use:   "list",
		Short: "List all transfer jobs",
		Long: `List all transfer jobs, with optional filtering by status.
Shows a summary of each job including completion status and transfer counts.`,
		RunE: jobListMain,
	}

	jobListStatus string
	jobListLimit  int
	jobListOffset int
)

func init() {
	jobListCmd.Flags().StringVarP(&jobListStatus, "status", "s", "", "Filter by status (pending, running, completed, failed, cancelled)")
	jobListCmd.Flags().IntVarP(&jobListLimit, "limit", "l", 10, "Maximum number of jobs to return")
	jobListCmd.Flags().IntVarP(&jobListOffset, "offset", "o", 0, "Offset for pagination")
	jobCmd.AddCommand(jobListCmd)
}

func jobListMain(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// Create API client
	apiClient, err := apiclient.NewAPIClient("")
	if err != nil {
		return errors.Wrap(err, "failed to create API client")
	}

	// Check if server is running
	if !apiClient.IsServerRunning(ctx) {
		return errors.New("API server is not running. Start it with: pelican client-api serve")
	}

	// List jobs
	resp, err := apiClient.ListJobs(ctx, jobListStatus, jobListLimit, jobListOffset)
	if err != nil {
		return errors.Wrap(err, "failed to list jobs")
	}

	if len(resp.Jobs) == 0 {
		fmt.Println("No jobs found")
		return nil
	}

	fmt.Printf("Total jobs: %d\n\n", resp.Total)
	fmt.Printf("%-40s %-12s %-20s %s\n", "Job ID", "Status", "Created", "Progress")
	fmt.Println("─────────────────────────────────────────────────────────────────────────────────────────────")

	for _, job := range resp.Jobs {
		progress := ""
		if job.TransfersTotal > 0 {
			progress = fmt.Sprintf("%d/%d transfers", job.TransfersCompleted, job.TransfersTotal)
			if job.TotalBytes > 0 {
				progress += fmt.Sprintf(", %s", formatBytes(job.BytesTransferred))
			}
		}

		fmt.Printf("%-40s %-12s %-20s %s\n",
			job.JobID,
			job.Status,
			job.CreatedAt.Format(time.RFC3339),
			progress)
	}

	if resp.Total > jobListLimit {
		fmt.Printf("\nShowing %d-%d of %d jobs\n", jobListOffset+1, jobListOffset+len(resp.Jobs), resp.Total)
	}

	return nil
}
