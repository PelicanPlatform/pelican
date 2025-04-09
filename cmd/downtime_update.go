package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/web_ui"
)

var downtimeUpdateCmd = &cobra.Command{
	Use:   "update [uuid]",
	Short: "Update an existing downtime period",
	Long:  "Interactively prompt for downtime fields and send a PUT request to update the specified downtime period. Press Enter without typing anything to leave a field unchanged.",
	Args:  cobra.ExactArgs(1),
	RunE:  updateDowntimeFunc,
}

func init() {
	flags := downtimeUpdateCmd.Flags()
	flags.StringP("server", "s", "", "Web URL of the target Pelican server (e.g. https://my-origin.com:8447)")
	downtimeUpdateCmd.MarkFlagRequired("server")
	flags.StringP("token", "t", "", "Path to the admin token file")
	downtimeCmd.AddCommand(downtimeUpdateCmd)
}

func updateDowntimeFunc(cmd *cobra.Command, args []string) error {
	downtimeUUID := args[0]
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// Initialize client
	if err := config.InitClient(); err != nil {
		log.Errorln("Failed to initialize client:", err)
	}

	serverURLStr, _ := cmd.Flags().GetString("server")
	tokenLocation, _ := cmd.Flags().GetString("token")

	apiURL, err := constructDowntimeApiURL(serverURLStr)
	if err != nil {
		return err
	}

	// Create a reader to prompt the user.
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Updating downtime record %s\n", downtimeUUID)
	fmt.Println("Press Enter without typing anything to leave a field unchanged.")

	// Build update payload (only non-empty values will be included)
	updatePayload := web_ui.DowntimeInput{}

	// Prompt for new Downtime Class
	fmt.Println("Select new downtime Class (or leave blank to keep unchanged):")
	classes := []string{
		string(server_structs.SCHEDULED),
		string(server_structs.UNSCHEDULED),
	}
	for {
		for i, cls := range classes {
			fmt.Printf("%d. %s\n", i+1, cls)
		}
		fmt.Print("Enter choice number: ")
		classInput, err := reader.ReadString('\n')
		if err != nil {
			return errors.Wrap(err, "failed to read downtime class")
		}
		classInput = strings.TrimSpace(classInput)
		if classInput == "" {
			break // leave unchanged
		}
		choice, err := strconv.Atoi(classInput)
		if err != nil || choice < 1 || choice > len(classes) {
			fmt.Println("Invalid downtime class selection. Please try again.")
			continue
		}
		updatePayload.Class = server_structs.Class(classes[choice-1])
		break
	}

	// Prompt for new Description
	fmt.Print("Enter new downtime Description (or leave blank to keep unchanged): ")
	description, err := reader.ReadString('\n')
	if err != nil {
		return errors.Wrap(err, "failed to read description")
	}
	description = strings.TrimSpace(description)
	if description != "" {
		updatePayload.Description = description
	}

	// Prompt for new Severity
	fmt.Println("Select new downtime Severity (or leave blank to keep unchanged):")
	severities := []string{
		string(server_structs.Outage),
		string(server_structs.Severe),
		string(server_structs.IntermittentOutage),
		string(server_structs.NoSignificantOutageExpected),
	}
	for {
		for i, sev := range severities {
			fmt.Printf("%d. %s\n", i+1, sev)
		}
		fmt.Print("Enter choice number: ")
		sevInput, err := reader.ReadString('\n')
		if err != nil {
			return errors.Wrap(err, "failed to read severity")
		}
		sevInput = strings.TrimSpace(sevInput)
		if sevInput == "" {
			break // leave unchanged
		}
		choice, err := strconv.Atoi(sevInput)
		if err != nil || choice < 1 || choice > len(severities) {
			fmt.Println("Invalid severity selection. Please try again.")
			continue
		}
		updatePayload.Severity = server_structs.Severity(severities[choice-1])
		break
	}

	// Prompt for new Start Time
	fmt.Print("Enter new start time in UTC (YYYY-MM-DD HH:MM:SS) (or leave blank to keep unchanged): ")
	startInput, err := reader.ReadString('\n')
	if err != nil {
		return errors.Wrap(err, "failed to read start time")
	}
	startInput = strings.TrimSpace(startInput)
	if startInput != "" {
		startTime, err := time.Parse("2006-01-02 15:04:05", startInput)
		if err != nil {
			return errors.Wrap(err, "Invalid start time format")
		}
		updatePayload.StartTime = startTime.UnixMilli()
	}

	// Prompt for new End Time
	fmt.Print("Enter new end time in UTC (YYYY-MM-DD HH:MM:SS), or '-1' for indefinite (or leave blank to keep unchanged): ")
	endInput, err := reader.ReadString('\n')
	if err != nil {
		return errors.Wrap(err, "failed to read end time")
	}
	endInput = strings.TrimSpace(endInput)
	if endInput != "" {
		var endTimeMilli int64
		if endInput == "-1" {
			endTimeMilli = -1
		} else {
			endTime, err := time.Parse("2006-01-02 15:04:05", endInput)
			if err != nil {
				return errors.Wrap(err, "Invalid end time format")
			}
			endTimeMilli = endTime.UnixMilli()
		}
		updatePayload.EndTime = endTimeMilli
	}

	// Marshal update payload.
	payloadBytes, err := json.Marshal(updatePayload)
	if err != nil {
		return errors.Wrap(err, "Failed to marshal update payload")
	}

	// Get token using your provided helper.
	tok, err := getToken(serverURLStr, tokenLocation)
	if err != nil {
		return err
	}

	// Build the API URL for update
	targetURL, err := url.Parse(apiURL.String() + "/" + downtimeUUID)
	if err != nil {
		return errors.Wrap(err, "Failed to build delete API URL")
	}

	// Prepare and send the HTTP request.
	req, err := http.NewRequestWithContext(ctx, "PUT", targetURL.String(), bytes.NewBuffer(payloadBytes))
	if err != nil {
		return errors.Wrap(err, "Failed to create HTTP request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	req.AddCookie(&http.Cookie{Name: "login", Value: tok})
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "pelican-client/"+config.GetVersion())

	httpClient := &http.Client{Transport: config.GetTransport()}
	resp, err := httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "HTTP request failed")
	}
	defer resp.Body.Close()

	bodyBytes, err := handleAdminApiResponse(resp)
	if err != nil {
		return errors.Wrap(err, "Server update request failed")
	}

	fmt.Println("Downtime updated successfully:")
	fmt.Println(string(bodyBytes))
	return nil
}
