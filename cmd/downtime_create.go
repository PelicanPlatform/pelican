package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_structs"
)

// downtimeCreateCmd creates a new downtime period interactively.
var downtimeCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new downtime period for the server",
	Long:  "Interactively prompt for downtime fields and send a POST request to create a new downtime period.",
	RunE:  createDowntimeFunc,
}

func init() {
	flags := downtimeCreateCmd.Flags()
	flags.StringP("server", "s", "", "Web URL of the target Pelican server (e.g. https://my-origin.com:8447)")
	downtimeCreateCmd.MarkFlagRequired("server")
	flags.StringP("token", "t", "", "Path to the admin token file")
	downtimeCmd.AddCommand(downtimeCreateCmd)
}

func createDowntimeFunc(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	if err := config.InitClient(); err != nil {
		log.Errorln("Failed to initialize client:", err)
	}

	serverURLStr, _ := cmd.Flags().GetString("server")
	tokenLocation, _ := cmd.Flags().GetString("token")

	targetURL, err := constructDowntimeApiURL(serverURLStr)
	if err != nil {
		return err
	}

	// Create a reader to prompt the user.
	reader := bufio.NewReader(os.Stdin)

	// Prompt for Downtime Class
	var downtimeClass string
	for {
		fmt.Println("Select downtime Class:")
		classes := []string{
			string(server_structs.SCHEDULED),
			string(server_structs.UNSCHEDULED),
		}
		for i, cls := range classes {
			fmt.Printf("%d. %s\n", i+1, cls)
		}
		fmt.Print("Enter choice number: ")
		classInput, err := reader.ReadString('\n')
		if err != nil {
			return errors.Wrap(err, "failed to read downtime class")
		}
		classInput = strings.TrimSpace(classInput)
		classChoice, err := strconv.Atoi(classInput)
		if err != nil || classChoice < 1 || classChoice > len(classes) {
			fmt.Println("Invalid downtime class selection. Please try again.")
			continue
		}
		downtimeClass = classes[classChoice-1]
		break
	}

	// Prompt for Description
	fmt.Print("Enter downtime Description: ")
	description, err := reader.ReadString('\n')
	if err != nil {
		return errors.Wrap(err, "failed to read description")
	}
	description = strings.TrimSpace(description)

	// Prompt for Severity
	var downtimeSeverity string
	for {
		fmt.Println("Select downtime Severity:")
		severities := []string{
			string(server_structs.Outage),
			string(server_structs.Severe),
			string(server_structs.IntermittentOutage),
			string(server_structs.NoSignificantOutageExpected),
		}
		for i, sev := range severities {
			fmt.Printf("%d. %s\n", i+1, sev)
		}
		fmt.Print("Enter number to choose: ")
		sevInput, err := reader.ReadString('\n')
		if err != nil {
			return errors.Wrap(err, "failed to read severity")
		}
		sevInput = strings.TrimSpace(sevInput)
		sevChoice, err := strconv.Atoi(sevInput)
		if err != nil || sevChoice < 1 || sevChoice > len(severities) {
			fmt.Println("Invalid severity selection. Please try again.")
			continue
		}
		downtimeSeverity = severities[sevChoice-1]
		break
	}

	// Prompt for Start Time
	fmt.Print("Enter start time in UTC (YYYY-MM-DD HH:MM:SS): ")
	startInput, err := reader.ReadString('\n')
	if err != nil {
		return errors.Wrap(err, "failed to read start time")
	}
	startInput = strings.TrimSpace(startInput)
	startTime, err := time.Parse("2006-01-02 15:04:05", startInput)
	if err != nil {
		return errors.Wrap(err, "Invalid start time format")
	}

	// Prompt for End Time
	fmt.Print("Enter end time in UTC (YYYY-MM-DD HH:MM:SS) or '-1' for indefinite: ")
	endInput, err := reader.ReadString('\n')
	if err != nil {
		return errors.Wrap(err, "failed to read end time")
	}
	endInput = strings.TrimSpace(endInput)
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

	// Build downtime payload
	downtimePayload := server_structs.Downtime{
		Class:       server_structs.Class(downtimeClass),
		Description: description,
		Severity:    server_structs.Severity(downtimeSeverity),
		StartTime:   startTime.UnixMilli(),
		EndTime:     endTimeMilli,
		// The server will set CreatedBy to "admin", based on the token
	}

	payloadBytes, err := json.Marshal(downtimePayload)
	if err != nil {
		return errors.Wrap(err, "Failed to marshal downtime payload")
	}

	// Get token using the provided helper.
	tok, err := getToken(serverURLStr, tokenLocation)
	if err != nil {
		return err
	}

	// Prepare and send the HTTP request.
	req, err := http.NewRequestWithContext(ctx, "POST", targetURL.String(), bytes.NewBuffer(payloadBytes))
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
		return errors.Wrap(err, "Server request failed")
	}

	fmt.Println("Downtime created successfully:")
	fmt.Println(string(bodyBytes))
	return nil
}
