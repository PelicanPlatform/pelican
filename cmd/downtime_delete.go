package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/config"
)

var downtimeDeleteCmd = &cobra.Command{
	Use:   "delete [uuid]",
	Short: "Delete a downtime period",
	Long:  "Delete the specified downtime period by UUID. Sends a DELETE request to the downtime API.",
	Args:  cobra.ExactArgs(1),
	RunE:  deleteDowntimeFunc,
}

func init() {
	flags := downtimeDeleteCmd.Flags()
	flags.StringP("server", "s", "", "Web URL of the target Pelican server (e.g. https://my-origin.com:8447)")
	downtimeDeleteCmd.MarkFlagRequired("server")
	flags.StringP("token", "t", "", "Path to the admin token file")
	downtimeCmd.AddCommand(downtimeDeleteCmd)
}

func deleteDowntimeFunc(cmd *cobra.Command, args []string) error {
	downtimeUUID := args[0]
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	if err := config.InitClient(); err != nil {
		log.Errorln("Failed to initialize client:", err)
	}

	// Get Flag Values
	serverURLStr, _ := cmd.Flags().GetString("server")
	tokenLocation, _ := cmd.Flags().GetString("token")

	// Basic validation of the input
	if serverURLStr == "" {
		return errors.New("The --server flag is required")
	}
	serverURLStr = strings.TrimSuffix(serverURLStr, "/")
	baseURL, err := url.Parse(serverURLStr)
	if err != nil {
		return errors.Wrapf(err, "Invalid server URL: %s", serverURLStr)
	}

	tok, err := getToken(serverURLStr, tokenLocation)
	if err != nil {
		return err
	}

	// Build the API URL for deletion.
	targetURL, err := baseURL.Parse(serverDowntimeAPIPath + "/" + downtimeUUID)
	if err != nil {
		return errors.Wrap(err, "Failed to build delete API URL")
	}

	log.Debugln("Deleting downtime from:", targetURL.String())

	req, err := http.NewRequestWithContext(ctx, "DELETE", targetURL.String(), nil)
	if err != nil {
		return errors.Wrap(err, "Failed to create HTTP request")
	}
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
		return errors.Wrap(err, "Server delete request failed")
	}

	fmt.Println("Downtime deleted successfully:")
	fmt.Println(string(bodyBytes))
	return nil
}
