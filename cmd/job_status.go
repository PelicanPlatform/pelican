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
	"context"
	"fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/client_agent"
	"github.com/pelicanplatform/pelican/client_agent/apiclient"
	"github.com/pelicanplatform/pelican/config"
)

var (
	jobStatusCmd = &cobra.Command{
		Use:   "status <job-id>",
		Short: "Get the status of a transfer job",
		Long: `Get detailed status information about a transfer job, including
the status of all transfers within the job and overall progress.`,
		Args: cobra.ExactArgs(1),
		RunE: jobStatusMain,
	}

	jobStatusWatch bool
)

func init() {
	jobStatusCmd.Flags().BoolVarP(&jobStatusWatch, "watch", "w", false, "Watch job status until completion")
	jobCmd.AddCommand(jobStatusCmd)
}

func jobStatusMain(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	jobID := args[0]

	// Initialize config to read parameters
	if err := config.InitClient(); err != nil {
		return errors.Wrap(err, "failed to initialize config")
	}

	// Create API client
	apiClient, err := apiclient.NewAPIClient("")
	if err != nil {
		return errors.Wrap(err, "failed to create API client")
	}

	// Check if server is running
	if !apiClient.IsServerRunning(ctx) {
		return errors.New("API server is not running. Start it with: pelican client-api serve")
	}

	if jobStatusWatch {
		return watchJobStatus(ctx, apiClient, jobID)
	}

	// Get status once
	status, err := apiClient.GetJobStatus(ctx, jobID)
	if err != nil {
		return errors.Wrap(err, "failed to get job status")
	}

	printJobStatus(status)
	return nil
}

func watchJobStatus(ctx context.Context, apiClient *apiclient.APIClient, jobID string) error {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			status, err := apiClient.GetJobStatus(ctx, jobID)
			if err != nil {
				return errors.Wrap(err, "failed to get job status")
			}

			// Clear screen and reprint status
			fmt.Print("\033[H\033[2J")
			printJobStatus(status)

			// Exit if job completed
			if status.Status == "completed" || status.Status == "failed" || status.Status == "cancelled" {
				return nil
			}
		}
	}
}

func printJobStatus(status *client_agent.JobStatus) {
	fmt.Printf("Job ID: %s\n", status.JobID)
	fmt.Printf("Status: %s\n", status.Status)
	fmt.Printf("Created: %s\n", status.CreatedAt.Format(time.RFC3339))

	if status.StartedAt != nil {
		fmt.Printf("Started: %s\n", status.StartedAt.Format(time.RFC3339))
	}

	if status.CompletedAt != nil {
		fmt.Printf("Completed: %s\n", status.CompletedAt.Format(time.RFC3339))
	}

	if status.Progress != nil {
		fmt.Printf("\nProgress:\n")
		fmt.Printf("  Transfers: %d/%d completed", status.Progress.TransfersCompleted, status.Progress.TransfersTotal)
		if status.Progress.TransfersFailed > 0 {
			fmt.Printf(" (%d failed)", status.Progress.TransfersFailed)
		}
		fmt.Println()

		if status.Progress.TotalBytes > 0 {
			fmt.Printf("  Data: %s / %s (%.1f%%)\n",
				formatBytes(status.Progress.BytesTransferred),
				formatBytes(status.Progress.TotalBytes),
				status.Progress.Percentage)
			fmt.Printf("  Rate: %.2f Mbps\n", status.Progress.TransferRateMbps)
		}
	}

	if len(status.Transfers) > 0 {
		fmt.Printf("\nTransfers:\n")
		for _, transfer := range status.Transfers {
			fmt.Printf("  [%s] %s -> %s (%s)\n",
				transfer.Status,
				transfer.Source,
				transfer.Destination,
				transfer.Operation)

			if transfer.Error != "" {
				fmt.Printf("    Error: %s\n", transfer.Error)
			}
		}
	}

	if status.Error != "" {
		fmt.Printf("\nError: %s\n", status.Error)
	}
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
