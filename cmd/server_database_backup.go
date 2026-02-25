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
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

var (
	serverDatabaseCmd = &cobra.Command{
		Use:   "database",
		Short: "Manage the Pelican server database",
		Long: `Provide commands for managing the Pelican server's SQLite database,
including backup creation, listing, verification, and restoration.`,
		Aliases: []string{"db"},
	}

	serverDatabaseBackupCmd = &cobra.Command{
		Use:   "backup",
		Short: "Manage database backups",
		Long: `Provide commands for creating, listing, verifying, and restoring
encrypted database backups.`,
	}

	serverDatabaseBackupCreateCmd = &cobra.Command{
		Use:   "create",
		Short: "Create a database backup now",
		Long: `Create a compressed and encrypted backup of the server database.
The backup is written to the configured backup directory
(Server.DatabaseBackup.Location) and encrypted with all available
issuer keys.`,
		Args:         cobra.NoArgs,
		RunE:         cliBackupCreate,
		SilenceUsage: true,
	}

	serverDatabaseBackupListCmd = &cobra.Command{
		Use:   "list",
		Short: "List available database backups",
		Long: `List all available database backup files in the configured backup
directory, showing filename, size, and timestamp. Output can be
formatted as JSON with the --json flag.`,
		Args:         cobra.NoArgs,
		RunE:         cliBackupList,
		Aliases:      []string{"ls"},
		SilenceUsage: true,
	}

	serverDatabaseBackupVerifyCmd = &cobra.Command{
		Use:   "verify [backup-file]",
		Short: "Verify a backup can be decrypted",
		Long: `Verify that a backup file can be successfully decrypted and
decompressed using the available issuer keys, without actually
restoring any data. If no file is specified, the most recent
backup is verified.`,
		Args:         cobra.MaximumNArgs(1),
		RunE:         cliBackupVerify,
		SilenceUsage: true,
	}

	serverDatabaseBackupRestoreCmd = &cobra.Command{
		Use:   "restore [backup-file]",
		Short: "Restore the database from a backup",
		Long: `Restore the server database from a specific backup file. If the
database already exists, the --force flag must be specified; in that
case the existing database is renamed with a .pre-restore suffix
before restoring.

If no backup file is specified by path, the most recent backup is
used when --latest is provided.

Use --output to restore to an alternate location (e.g. for
inspection) instead of the configured database path.`,
		Args:         cobra.MaximumNArgs(1),
		RunE:         cliBackupRestore,
		SilenceUsage: true,
	}

	serverDatabaseBackupInfoCmd = &cobra.Command{
		Use:   "info [backup-file]",
		Short: "Show metadata for a backup file",
		Long: `Display the human-readable metadata stored in a backup file,
including the hostname, username, Pelican version, server URL,
and timestamp of when the backup was created. This information
is stored unencrypted and can be read without issuer keys.

If no file is specified, the most recent backup is used.`,
		Args:         cobra.MaximumNArgs(1),
		RunE:         cliBackupInfo,
		SilenceUsage: true,
	}
)

// initServerForBackup initializes server configuration so that issuer keys
// and database paths are available. Since backup commands are offline
// operations, we do not start any listeners. The serverType parameter
// controls which configuration subset is loaded. For backup purposes we
// use a generic server initialization approach.
func initServerForBackup(ctx context.Context) error {
	// Attempt to initialize server config, arbitrarily picking `OriginType`.
	if err := config.InitServer(ctx, server_structs.OriginType); err != nil {
		return errors.Wrap(err, "failed to initialize server configuration")
	}
	return nil
}

func cliBackupCreate(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	if err := initServerForBackup(ctx); err != nil {
		return err
	}

	// Initialize the database handle so VACUUM INTO works.
	dbPath := param.Server_DbLocation.GetString()
	if dbPath == "" {
		return errors.New("Server.DbLocation is not configured")
	}

	// We need the database open for VACUUM INTO. Passing 0 as server type
	// opens the database without running any type-specific migrations,
	// which is appropriate for backup commands that only need read access.
	if database.ServerDatabase == nil {
		if err := database.InitServerDatabase(0); err != nil {
			return errors.Wrap(err, "failed to initialize database for backup")
		}
		defer func() {
			if err := database.ShutdownDB(); err != nil {
				log.Warnf("Failed to shut down database: %v", err)
			}
		}()
	}

	if err := database.CreateBackup(ctx); err != nil {
		return errors.Wrap(err, "failed to create backup")
	}

	if outputJSON {
		backups, _ := database.ListBackups()
		result := map[string]interface{}{"status": "created"}
		if len(backups) > 0 {
			result["backup"] = backups[0]
		}
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	fmt.Println("Backup created successfully.")
	return nil
}

func cliBackupList(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	if err := initServerForBackup(ctx); err != nil {
		return err
	}

	backups, err := database.ListBackups()
	if err != nil {
		return err
	}

	if len(backups) == 0 {
		if outputJSON {
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode([]database.BackupInfo{})
		}
		fmt.Println("No backups found.")
		return nil
	}

	if outputJSON {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(backups)
	}

	// Table-style output.
	fmt.Printf("%-50s  %12s  %s\n", "NAME", "SIZE", "TIMESTAMP")
	for _, b := range backups {
		tsStr := "(unknown)"
		if !b.Timestamp.IsZero() {
			tsStr = b.Timestamp.Format(time.RFC3339)
		}
		sizeStr := formatSize(b.Size)
		fmt.Printf("%-50s  %12s  %s\n", b.Name, sizeStr, tsStr)
	}

	noun := "backups"
	if len(backups) == 1 {
		noun = "backup"
	}
	fmt.Printf("\n%d %s found in %s\n", len(backups), noun,
		param.Server_DatabaseBackup_Location.GetString())
	return nil
}

func cliBackupVerify(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	if err := initServerForBackup(ctx); err != nil {
		return err
	}

	var backupPath string
	if len(args) == 1 {
		backupPath = args[0]
	} else {
		backups, err := database.ListBackups()
		if err != nil {
			return err
		}
		if len(backups) == 0 {
			return errors.New("no backups available to verify")
		}
		backupPath = backups[0].Path
		if !outputJSON {
			fmt.Printf("Verifying most recent backup: %s\n", backupPath)
		}
	}
	if err := database.VerifyBackup(backupPath); err != nil {
		if outputJSON {
			result := map[string]interface{}{
				"status": "failed",
				"path":   backupPath,
				"error":  err.Error(),
			}
			var noKey *database.ErrNoMatchingKey
			if errors.As(err, &noKey) {
				result["required_key_ids"] = noKey.RequiredKeyIDs
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			_ = enc.Encode(result)
		}
		return errors.Wrapf(err, "backup verification failed for %s", backupPath)
	}

	if outputJSON {
		result := map[string]interface{}{
			"status": "valid",
			"path":   backupPath,
		}
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	fmt.Printf("Backup %s is valid.\n", backupPath)
	return nil
}

func cliBackupRestore(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	if err := initServerForBackup(ctx); err != nil {
		return err
	}

	force, _ := cmd.Flags().GetBool("force")
	latest, _ := cmd.Flags().GetBool("latest")

	var backupPath string
	if len(args) == 1 {
		backupPath = args[0]
	} else if latest {
		backups, err := database.ListBackups()
		if err != nil {
			return err
		}
		if len(backups) == 0 {
			return errors.New("no backups available to restore from")
		}
		backupPath = backups[0].Path
		if !outputJSON {
			fmt.Printf("Using most recent backup: %s\n", backupPath)
		}
	} else {
		return errors.New("specify a backup file path, or use --latest to restore the most recent backup")
	}

	dbPath, _ := cmd.Flags().GetString("output")
	if dbPath == "" {
		dbPath = param.Server_DbLocation.GetString()
	}
	if err := database.RestoreFromSpecificBackup(dbPath, backupPath, force); err != nil {
		if outputJSON {
			result := map[string]interface{}{
				"status": "failed",
				"source": backupPath,
				"target": dbPath,
				"error":  err.Error(),
			}
			var noKey *database.ErrNoMatchingKey
			if errors.As(err, &noKey) {
				result["required_key_ids"] = noKey.RequiredKeyIDs
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			_ = enc.Encode(result)
		}
		if errors.Is(err, database.ErrDatabaseExists) {
			return fmt.Errorf("%w; use --force to overwrite or --output to specify an alternate location", err)
		}
		return err
	}

	if outputJSON {
		result := map[string]interface{}{
			"status": "restored",
			"source": backupPath,
			"target": dbPath,
		}
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	fmt.Printf("Database restored from %s to %s\n", backupPath, dbPath)
	return nil
}

// formatSize returns a human-friendly file size string.
func formatSize(bytes int64) string {
	const (
		kb = 1024
		mb = kb * 1024
		gb = mb * 1024
	)
	switch {
	case bytes >= gb:
		return fmt.Sprintf("%.1f GiB", float64(bytes)/float64(gb))
	case bytes >= mb:
		return fmt.Sprintf("%.1f MiB", float64(bytes)/float64(mb))
	case bytes >= kb:
		return fmt.Sprintf("%.1f KiB", float64(bytes)/float64(kb))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

func cliBackupInfo(cmd *cobra.Command, args []string) error {
	var backupPath string
	if len(args) == 1 {
		backupPath = args[0]
	} else {
		// Need server config to find the backup directory.
		ctx, cancel := context.WithCancel(cmd.Context())
		defer cancel()
		if err := initServerForBackup(ctx); err != nil {
			return err
		}
		backups, err := database.ListBackups()
		if err != nil {
			return err
		}
		if len(backups) == 0 {
			return errors.New("no backups available")
		}
		backupPath = backups[0].Path
		if !outputJSON {
			fmt.Printf("Showing metadata for most recent backup: %s\n\n", backupPath)
		}
	}

	meta, err := database.ReadBackupMetadata(backupPath)
	if err != nil {
		return errors.Wrapf(err, "failed to read metadata from %s", backupPath)
	}

	if meta == nil {
		if outputJSON {
			result := map[string]interface{}{
				"path":   backupPath,
				"status": "no_metadata",
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(result)
		}
		fmt.Printf("Backup %s does not contain a metadata block (older format).\n", backupPath)
		return nil
	}

	if outputJSON {
		result := map[string]interface{}{
			"path":     backupPath,
			"metadata": meta,
		}
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	// Human-readable table.
	fmt.Printf("%-18s %s\n", "Format Version:", meta.FormatVersion)
	fmt.Printf("%-18s %s\n", "Timestamp:", meta.Timestamp)
	fmt.Printf("%-18s %s\n", "Pelican Version:", meta.PelicanVersion)
	if meta.Hostname != "" {
		fmt.Printf("%-18s %s\n", "Hostname:", meta.Hostname)
	}
	if meta.Username != "" {
		fmt.Printf("%-18s %s\n", "Username:", meta.Username)
	}
	if meta.ServerURL != "" {
		fmt.Printf("%-18s %s\n", "Server URL:", meta.ServerURL)
	}
	if meta.DatabasePath != "" {
		fmt.Printf("%-18s %s\n", "Database Path:", meta.DatabasePath)
	}
	fmt.Printf("%-18s %s/%s\n", "Platform:", meta.GOOS, meta.GOARCH)

	return nil
}

func init() {
	// Build the command tree: pelican server database backup {create,list,verify,restore}
	serverCmd.AddCommand(serverDatabaseCmd)
	serverDatabaseCmd.AddCommand(serverDatabaseBackupCmd)

	serverDatabaseBackupCmd.AddCommand(serverDatabaseBackupCreateCmd)
	serverDatabaseBackupCmd.AddCommand(serverDatabaseBackupListCmd)
	serverDatabaseBackupCmd.AddCommand(serverDatabaseBackupVerifyCmd)
	serverDatabaseBackupCmd.AddCommand(serverDatabaseBackupRestoreCmd)
	serverDatabaseBackupCmd.AddCommand(serverDatabaseBackupInfoCmd)

	// Restore-specific flags.
	serverDatabaseBackupRestoreCmd.Flags().Bool("force", false,
		"Overwrite an existing database (backs up the current one first)")
	serverDatabaseBackupRestoreCmd.Flags().Bool("latest", false,
		"Restore the most recent backup instead of specifying a file")
	serverDatabaseBackupRestoreCmd.Flags().StringP("output", "o", "",
		"Restore to this path instead of the configured database location")
}
