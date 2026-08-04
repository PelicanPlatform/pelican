//go:build server

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

// Operator commands for a pstore-backed origin.
//
// A pstore keeps its namespace in an encrypted embedded database and its
// object data in encrypted block files, so none of it can be inspected with
// ls, du, or md5sum the way a POSIX origin's storage can.  These commands are
// the substitute.
//
// They all require the origin to be stopped: the store takes its directory
// lock exclusively, and a consistency check against a live origin would be
// racing writes anyway.

package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/local_cache"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pstore"
	"github.com/pelicanplatform/pelican/utils"
)

var (
	pstoreRepair      bool
	pstoreDeep        bool
	pstoreKeyFile     string
	pstoreFileKeyFile string

	pstoreExportTo  string
	pstoreVerify    bool
	pstoreDryRun    bool
	pstoreLongList  bool
	pstoreRecursive bool
	pstoreResume    bool

	originPStoreCmd = &cobra.Command{
		Use:   "pstore",
		Short: "Inspect and repair a Pelican store",
		Long: `Inspect the contents of an origin backed by the Pelican store ("pstore").

A pstore keeps its namespace in an encrypted database and its objects in
encrypted block files, so its contents cannot be examined with ordinary
filesystem tools. These commands read the store directly.

The origin must be stopped: the store holds its directory lock exclusively.

The store location comes from Origin.PStoreLocation, or from --location.`,
		SilenceUsage: true,
	}

	originPStoreLsCmd = &cobra.Command{
		Use:   "ls [path]",
		Short: "List a directory in the store",
		Long: `List the direct children of a directory inside the store.

Examples:
  pelican-server origin pstore ls /
  pelican-server origin pstore ls -l /data
  pelican-server origin pstore ls -R /data`,
		Args:         cobra.MaximumNArgs(1),
		RunE:         runPStoreLs,
		SilenceUsage: true,
	}

	originPStoreStatCmd = &cobra.Command{
		Use:          "stat <path>",
		Short:        "Show an object's metadata",
		Args:         cobra.ExactArgs(1),
		RunE:         runPStoreStat,
		SilenceUsage: true,
	}

	originPStoreDuCmd = &cobra.Command{
		Use:   "du [path]",
		Short: "Report space used",
		Long: `Report the space a subtree occupies, and the store's overall usage.

Sizes are object content lengths; the store's total additionally reflects the
per-block overhead that encrypted blocks carry on disk.`,
		Args:         cobra.MaximumNArgs(1),
		RunE:         runPStoreDu,
		SilenceUsage: true,
	}

	originPStoreFsckCmd = &cobra.Command{
		Use:   "fsck",
		Short: "Check the store's internal consistency",
		Long: `Check the store for inconsistencies and optionally repair them.

Reports directory entries whose object data is missing, object versions no
entry refers to, writes that never completed, and usage counters that have
drifted.

Without --repair nothing is modified. With it, unservable entries are removed,
orphaned versions are queued for reclamation, and the counters are resynced.

--deep additionally reads every object back and checks it against the
checksums recorded when it was written. That is the only way to detect at-rest
corruption -- a flipped bit in a block file -- since every other check reads
only the catalog. It costs a full pass over the data.`,
		Args:         cobra.NoArgs,
		RunE:         runPStoreFsck,
		SilenceUsage: true,
	}

	originPStoreBackupCmd = &cobra.Command{
		Use:   "metadata-backup <file>",
		Short: "Back up the store's metadata (not its object data)",
		Long: `Back up the store's metadata to a file.

THIS DOES NOT BACK UP OBJECT DATA. It covers the catalog: the directory tree,
and each object's size, checksums, and where its blocks live. Restoring it
gives back the namespace, not the bytes.

An origin cannot re-fetch what it loses. Object data on disk is encrypted and
named by hash; the namespace, each object's data key, its size, and its
checksums all live in the catalog, so a store whose catalog is gone is a
directory of unreadable bytes.

A metadata backup covers the catalog only. Restoring one is useful only
alongside:

  - the object data, which ordinary filesystem backup tools handle; and
  - masterkey.json in the store directory, which wraps the encryption key and
    is itself protected by the origin's issuer keys.

The backup is always encrypted. A snapshot is a logical dump: it holds every
object path and the salt that keeps on-disk filenames unguessable, so there is
no option to write one in the clear.

The body is encrypted under a key belonging to this file alone, derived from the
origin's backup key and a random salt stored in the file. The backup key itself
travels inside the file, sealed to every issuer key that is current now, so any
one of them opens it. Pass --key-file to seal it to a backup key of your own
instead of the origin's issuer keys.

Three things open the finished file: any of those issuer keys, the backup key
from "pstore metadata-backup-key", or this one file's own key from "pstore
metadata-backup-key <file>".

Set Origin.PStoreMetadataBackupLocation to have the origin back itself up on a
timer, which works while it is running. This command is for taking one by hand.`,
		Args:         cobra.ExactArgs(1),
		RunE:         runPStoreBackup,
		SilenceUsage: true,
	}

	originPStoreRestoreCmd = &cobra.Command{
		Use:   "metadata-restore <file>",
		Short: "Restore a metadata backup into an empty store",
		Long: `Restore a metadata backup taken by "pstore metadata-backup".

This restores the namespace only. The object data must already be in place --
a restore into an empty directory produces a store that lists every object and
can serve none of them.

The target store must be empty: restoring over live records would interleave
two namespaces rather than replace one. Restore into a fresh directory
alongside the object data and masterkey.json the backup was taken with, then
point the origin at it.

Every metadata backup is complete in itself; there are no incremental backups
to chain, precisely because the target must be empty.

The backup is opened with the origin's issuer keys, so on the origin itself
nothing more is needed. Elsewhere -- or if those keys are gone -- pass either:

  --key-file  the backup key from "pstore metadata-backup-key", which opens
              every backup this origin has written; or
  --file-key  this one file's own key, from "pstore metadata-backup-key <file>",
              which opens this file and no other.

Which container the file is in is read from the file itself. A backup written
in a format version this build does not read is refused by version number
rather than decoded.`,
		Args:         cobra.ExactArgs(1),
		RunE:         runPStoreRestore,
		SilenceUsage: true,
	}

	originPStoreBackupKeyCmd = &cobra.Command{
		Use:   "metadata-backup-key [backup-file]",
		Short: "Print the key that opens this origin's metadata backups, or one file's own key",
		Long: `Print a metadata backup key. There are two of them, and which one you get
depends on whether you name a file.

  metadata-backup-key            the BACKUP KEY: opens EVERY metadata backup
                                 this origin has written or will write
  metadata-backup-key <file>     that ONE FILE'S KEY: opens exactly the named
                                 backup and no other

Keys are DERIVED, not generated. The backup key comes from the origin's issuer
keys, and a file's key comes from the backup key plus a random salt stored in
that file, so running either form twice prints the same answer. There is nothing
to create, configure, or lose track of, and metadata backups are always
encrypted whether or not this command is ever run.

WITHOUT A FILE -- the backup key, for escrow.

Every backup carries this key inside it, sealed to each issuer key that was
current when the backup was written, so a restore on the origin itself needs
nothing but those issuer keys. This form exists for when they are gone too. Save
what it prints somewhere the backups are not, and any backup can still be
restored on a machine that has never seen this origin:

  pelican-server origin pstore metadata-backup-key > /etc/pelican/pstore-backup.key
  chmod 600 /etc/pelican/pstore-backup.key
  pelican-server origin pstore metadata-restore --key-file /etc/pelican/pstore-backup.key <file>

A metadata backup and this key together are equivalent to the store's namespace
in cleartext, so keep them apart.

WITH A FILE -- that file's own key, for handing out one backup.

Each backup is encrypted under a key of its very own. This form reads the salt
out of the named file and re-derives that key, using the origin's issuer keys or,
with --key-file, an escrowed backup key -- so an operator holding only the
escrowed key can still produce a specific file's key without the issuer keys:

  pelican-server origin pstore metadata-backup-key /backups/pstore-metadata-....pmb
  pelican-server origin pstore metadata-restore --file-key thatfile.key /backups/pstore-metadata-....pmb

The printed key opens THAT file only. It says nothing about any other backup, so
it is what to give to whoever is restoring one archive, rather than the backup
key above.

Rotating the origin's issuer keys changes what the no-file form prints. Backups
written before the rotation are still opened by the key printed before it, and by
the issuer keys they were sealed to that survived it -- so re-run this after a
rotation and keep both.

These keys are specific to pstore metadata backups. They descend from a
different label than the server database's backup key and will not open a
database backup.`,
		Args:         cobra.MaximumNArgs(1),
		RunE:         runPStoreBackupKey,
		SilenceUsage: true,
	}

	originPStoreExportCmd = &cobra.Command{
		Use:   "export [path]",
		Short: "Write objects out as ordinary files",
		Long: `Export a subtree from the store into a directory of plain files.

This is the recovery path that does not need Pelican running: the objects come
out as normal files in a normal directory tree, readable with anything.

Objects that cannot be read are reported and skipped rather than aborting the
export, because recovering most of a damaged store and knowing exactly what was
lost is more useful than stopping at the first bad block.

An export never overwrites what is already in the destination. Pass --resume to
continue an interrupted export: files already written are skipped and counted
separately rather than reported as failures.`,
		Args:         cobra.MaximumNArgs(1),
		RunE:         runPStoreExport,
		SilenceUsage: true,
	}

	originPStoreDigestCmd = &cobra.Command{
		Use:   "digest <path>",
		Short: "Show the checksums recorded for an object",
		Long: `Show the checksums computed when the object was written.

These are the values the origin serves in response to Want-Digest.`,
		Args:         cobra.ExactArgs(1),
		RunE:         runPStoreDigest,
		SilenceUsage: true,
	}
)

func init() {
	originCmd.AddCommand(originPStoreCmd)
	originPStoreCmd.AddCommand(originPStoreLsCmd)
	originPStoreCmd.AddCommand(originPStoreStatCmd)
	originPStoreCmd.AddCommand(originPStoreDuCmd)
	originPStoreCmd.AddCommand(originPStoreFsckCmd)
	originPStoreCmd.AddCommand(originPStoreDigestCmd)
	originPStoreCmd.AddCommand(originPStoreBackupCmd)
	originPStoreCmd.AddCommand(originPStoreRestoreCmd)
	originPStoreCmd.AddCommand(originPStoreBackupKeyCmd)
	originPStoreCmd.AddCommand(originPStoreExportCmd)

	originPStoreCmd.PersistentFlags().String("location", "",
		"Store directory (defaults to Origin.PStoreLocation)")
	originPStoreLsCmd.Flags().BoolVarP(&pstoreLongList, "long", "l", false,
		"Show size, modification time, and ETag")
	originPStoreLsCmd.Flags().BoolVarP(&pstoreRecursive, "recursive", "R", false,
		"Descend into subdirectories")
	originPStoreFsckCmd.Flags().BoolVar(&pstoreRepair, "repair", false,
		"Repair the problems found instead of only reporting them")
	originPStoreBackupCmd.Flags().StringVar(&pstoreKeyFile, "key-file", "",
		"Seal the backup to the backup key in this file instead of the origin's issuer keys")
	originPStoreRestoreCmd.Flags().StringVar(&pstoreKeyFile, "key-file", "",
		"Open the backup with the backup key in this file instead of the origin's issuer "+
			"keys (see `metadata-backup-key`)")
	originPStoreRestoreCmd.Flags().StringVar(&pstoreFileKeyFile, "file-key", "",
		"Open the backup with this one archive's own key, read from this file "+
			"(see `metadata-backup-key <file>`)")
	originPStoreBackupKeyCmd.Flags().StringVar(&pstoreKeyFile, "key-file", "",
		"Derive the named file's key from the backup key in this file instead of the "+
			"origin's issuer keys")
	originPStoreExportCmd.Flags().StringVar(&pstoreExportTo, "to", "",
		"Directory to write the exported files into (required)")
	originPStoreExportCmd.Flags().BoolVar(&pstoreVerify, "verify", false,
		"Check each object against its stored checksums as it is written")
	originPStoreExportCmd.Flags().BoolVar(&pstoreDryRun, "dry-run", false,
		"Report what would be written without writing it")
	originPStoreExportCmd.Flags().BoolVar(&pstoreResume, "resume", false,
		"Skip objects already present in the destination instead of reporting them")
	originPStoreFsckCmd.Flags().BoolVar(&pstoreDeep, "deep", false,
		"Also read every object back and verify it against its stored checksums")
}

// openPStoreForCLI opens the configured store for offline maintenance.
//
// Inspection commands pass allowWrites=false so a mistake cannot modify the
// store; only fsck --repair asks for write access.
func openPStoreForCLI(cmd *cobra.Command, allowWrites bool) (*pstore.Store, error) {
	if err := config.InitClient(); err != nil {
		return nil, errors.Wrap(err, "failed to initialize configuration")
	}
	// The catalog's master key is wrapped under the origin's issuer private
	// keys, so they must be loaded before the store can be opened.  This
	// deliberately avoids config.InitServer, which brings up far more of the
	// origin than reading a database needs.
	if _, err := config.GetIssuerPublicJWKS(); err != nil {
		return nil, errors.Wrap(err,
			"failed to load the origin's issuer keys, which the store is encrypted under")
	}

	location, err := cmd.Flags().GetString("location")
	if err != nil {
		return nil, err
	}
	if location == "" {
		location = param.Origin_PStoreLocation.GetString()
	}
	if location == "" {
		return nil, errors.Errorf("no store location; set %s or pass --location",
			param.Origin_PStoreLocation.GetName())
	}

	store, err := pstore.OpenMaintenance(cmd.Context(), location, allowWrites)
	if err != nil {
		// A running origin holding the directory lock is the overwhelmingly
		// likely cause, and BadgerDB's own message about it is not obvious.
		return nil, errors.Wrapf(err,
			"failed to open the store at %s (is the origin still running?)", location)
	}
	return store, nil
}

func pstorePathArg(args []string) string {
	if len(args) == 0 {
		return "/"
	}
	return args[0]
}

func runPStoreLs(cmd *cobra.Command, args []string) error {
	store, err := openPStoreForCLI(cmd, false)
	if err != nil {
		return err
	}
	defer store.Close()

	root := pstorePathArg(args)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()

	if pstoreLongList {
		fmt.Fprintln(w, "MODE\tSIZE\tMODIFIED\tETAG\tNAME")
	}
	return pstoreWalk(store, root, func(dir string, e pstore.ListEntry) {
		name := e.Name
		if pstoreRecursive && dir != "/" {
			name = dir + "/" + e.Name
		} else if pstoreRecursive {
			name = "/" + e.Name
		}
		if !pstoreLongList {
			if e.Dirent.IsDir() {
				name += "/"
			}
			fmt.Fprintln(w, name)
			return
		}
		kind := "-"
		size := utils.HumanBytes(e.Dirent.Size)
		if e.Dirent.IsDir() {
			kind = "d"
			size = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			kind, size,
			time.Unix(0, e.Dirent.MTimeNanos).Format(time.RFC3339),
			shortETag(e.Dirent.Generation), name)
	})
}

// pstoreWalkPageSize bounds how much of a directory is held at once.
//
// A pstore is built for millions of objects in a single directory, so
// materialising a listing is not a shortcut -- `du /` on a real store would
// hold the whole namespace, and with --recursive one page per level of depth
// on top of that. The recovery export already pages for the same reason.
const pstoreWalkPageSize = 512

// pstoreWalk visits a directory, descending when --recursive is set.
//
// Recursion happens while the page is still in hand rather than after the
// whole directory has been read, so the peak is one page per level of nesting
// instead of one directory per level.
func pstoreWalk(store *pstore.Store, dir string, visit func(string, pstore.ListEntry)) error {
	after := ""
	for {
		entries, more, err := store.List(dir, after, pstoreWalkPageSize)
		if err != nil {
			return errors.Wrapf(err, "cannot list %s", dir)
		}
		if len(entries) == 0 {
			return nil
		}
		for _, e := range entries {
			visit(dir, e)
		}
		if pstoreRecursive {
			for _, e := range entries {
				if !e.Dirent.IsDir() {
					continue
				}
				child := dir + "/" + e.Name
				if dir == "/" {
					child = "/" + e.Name
				}
				if err := pstoreWalk(store, child, visit); err != nil {
					return err
				}
			}
		}
		if !more {
			return nil
		}
		after = entries[len(entries)-1].Name
	}
}

func runPStoreStat(cmd *cobra.Command, args []string) error {
	store, err := openPStoreForCLI(cmd, false)
	if err != nil {
		return err
	}
	defer store.Close()

	d, err := store.Stat(args[0])
	if err != nil {
		return errors.Wrapf(err, "cannot stat %s", args[0])
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()
	fmt.Fprintf(w, "Path:\t%s\n", args[0])
	if d.IsDir() {
		fmt.Fprintf(w, "Type:\tdirectory\n")
	} else {
		fmt.Fprintf(w, "Type:\tobject\n")
		fmt.Fprintf(w, "Size:\t%d (%s)\n", d.Size, utils.HumanBytes(d.Size))
		fmt.Fprintf(w, "ETag:\t\"%s\"\n", d.Generation)
	}
	fmt.Fprintf(w, "Modified:\t%s\n", time.Unix(0, d.MTimeNanos).Format(time.RFC3339))

	if !d.IsDir() {
		if atime, aErr := store.AccessTime(args[0]); aErr == nil && !atime.IsZero() {
			fmt.Fprintf(w, "Accessed:\t%s\n", atime.Format(time.RFC3339))
		} else if aErr == nil {
			fmt.Fprintf(w, "Accessed:\tnever read since it was written\n")
		}
		if digests, dErr := store.Digests(args[0]); dErr == nil && len(digests) > 0 {
			fmt.Fprintf(w, "Digests:\t%s\n", local_cache.FormatDigestHeader(digests))
		}
	}
	return nil
}

func runPStoreDu(cmd *cobra.Command, args []string) error {
	store, err := openPStoreForCLI(cmd, false)
	if err != nil {
		return err
	}
	defer store.Close()

	root := pstorePathArg(args)
	var files, dirs int
	var bytes int64
	// Recurse regardless of the ls flag: du is inherently a subtree total.
	prev := pstoreRecursive
	pstoreRecursive = true
	defer func() { pstoreRecursive = prev }()

	if err := pstoreWalk(store, root, func(_ string, e pstore.ListEntry) {
		if e.Dirent.IsDir() {
			dirs++
			return
		}
		files++
		bytes += e.Dirent.Size
	}); err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()
	fmt.Fprintf(w, "Path:\t%s\n", root)
	fmt.Fprintf(w, "Objects:\t%d\n", files)
	fmt.Fprintf(w, "Directories:\t%d\n", dirs)
	fmt.Fprintf(w, "Content bytes:\t%d (%s)\n", bytes, utils.HumanBytes(bytes))

	used, max := store.Usage()
	fmt.Fprintf(w, "\nStore used:\t%s\n", utils.HumanBytes(used))
	if max > 0 {
		fmt.Fprintf(w, "Store capacity:\t%s (%.1f%% used)\n",
			utils.HumanBytes(max), 100*float64(used)/float64(max))
	} else {
		fmt.Fprintf(w, "Store capacity:\tunbounded\n")
	}
	return nil
}

func runPStoreFsck(cmd *cobra.Command, args []string) error {
	store, err := openPStoreForCLI(cmd, pstoreRepair)
	if err != nil {
		return err
	}
	defer store.Close()

	report, err := store.FsckWith(cmd.Context(), pstore.FsckOptions{
		Repair: pstoreRepair,
		Deep:   pstoreDeep,
	})
	if err != nil {
		return errors.Wrap(err, "consistency check failed")
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Entries scanned:\t%d\n", report.EntriesScanned)
	fmt.Fprintf(w, "Directories:\t%d\n", report.DirectoriesScanned)
	if pstoreDeep {
		fmt.Fprintf(w, "Objects verified:\t%d\n", report.ObjectsVerified)
	}
	w.Flush()

	if len(report.PendingInstances) > 0 {
		// Not a fault: an object whose write is still in flight has metadata
		// before it has a directory entry.  Shown so the count is not
		// mistaken for something missing.
		fmt.Fprintf(w, "Writes in flight:\t%d\n", len(report.PendingInstances))
		w.Flush()
	}

	if report.Healthy() {
		fmt.Println("\nNo problems found.")
		return nil
	}

	// What repair acted on and what it did not are two different lists, and
	// printing them under one heading is how an operator comes to believe a
	// store with corrupt objects in it was fixed.
	unresolved := report.Unresolved()
	if resolved := report.Resolved(); len(resolved) > 0 {
		fmt.Println("\nRepaired:")
		for _, item := range resolved {
			fmt.Printf("  %s\n", item)
		}
	}
	if len(unresolved) > 0 {
		if report.Repaired {
			fmt.Println("\nNOT repaired -- these need a decision that fsck cannot make:")
		} else {
			fmt.Println("\nFound:")
		}
		for _, item := range unresolved {
			fmt.Printf("  %s\n", item)
		}
	}

	fmt.Println()
	reportList("Entries whose object data is missing", report.DanglingEntries)
	reportList("Writes that never completed", report.MissingData)
	reportList("Object versions no entry refers to", report.OrphanedInstances)
	reportList("Objects whose data no longer matches its checksums", report.CorruptObjects)
	if len(report.UsageDrift) > 0 {
		fmt.Println("Usage counter drift (actual minus recorded):")
		ids := make([]int, 0, len(report.UsageDrift))
		for id := range report.UsageDrift {
			ids = append(ids, int(id))
		}
		sort.Ints(ids)
		for _, id := range ids {
			fmt.Printf("  storage directory %d: %+d bytes\n", id, report.UsageDrift[local_cache.StorageID(id)])
		}
		fmt.Println()
	}

	if report.Repaired && len(report.OrphanedInstances) > 0 {
		fmt.Println("Reclamation of orphaned data happens on the origin's next run.")
	}
	if len(unresolved) == 0 {
		return nil
	}
	// A non-zero exit lets this drive monitoring without parsing the output.
	// It must stay non-zero after --repair when findings remain, or a
	// monitoring script reads "success" off a store full of corrupt objects.
	if report.Repaired {
		return errors.Errorf("%d finding(s) could not be repaired; see above", len(unresolved))
	}
	return errors.New("the store has inconsistencies; re-run with --repair to fix them")
}

func reportList(title string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Printf("%s (%d):\n", title, len(items))
	const maxShown = 20
	for i, item := range items {
		if i == maxShown {
			fmt.Printf("  ... and %d more\n", len(items)-maxShown)
			break
		}
		fmt.Printf("  %s\n", item)
	}
	fmt.Println()
}

func runPStoreDigest(cmd *cobra.Command, args []string) error {
	store, err := openPStoreForCLI(cmd, false)
	if err != nil {
		return err
	}
	defer store.Close()

	digests, err := store.Digests(args[0])
	if err != nil {
		return errors.Wrapf(err, "cannot read digests for %s", args[0])
	}
	if len(digests) == 0 {
		// Every pstore write records checksums as it ingests, so an object
		// without them did not finish being written -- there was never a
		// released version that skipped the step.
		return errors.Errorf("no checksums recorded for %s; its write did not complete. "+
			"Run `pelican-server origin pstore fsck` to see whether the entry is servable at all",
			args[0])
	}

	// Rendered exactly as the origin would serve them in a Digest header, so
	// an operator can compare the two directly.
	entries := make([]string, 0, len(digests))
	for _, c := range digests {
		if entry := local_cache.FormatDigestEntry(c); entry != "" {
			entries = append(entries, entry)
		}
	}
	sort.Strings(entries)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()
	for _, entry := range entries {
		name, value, _ := strings.Cut(entry, "=")
		fmt.Fprintf(w, "%s\t%s\n", name, value)
	}
	return nil
}

// shortETag abbreviates a generation for column output.
func shortETag(generation string) string {
	if generation == "" {
		return "-"
	}
	if len(generation) > 12 {
		return generation[:12] + "..."
	}
	return generation
}

func runPStoreBackup(cmd *cobra.Command, args []string) error {
	store, err := openPStoreForCLI(cmd, false)
	if err != nil {
		return err
	}
	defer store.Close()

	// Exclusive create: silently overwriting a previous backup is not a
	// mistake worth allowing in a recovery tool.
	f, err := os.OpenFile(args[0], os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.Wrapf(err, "cannot create %s", args[0])
	}
	defer f.Close()

	keys, err := pstoreBackupKeys()
	if err != nil {
		return err
	}
	if _, err = store.BackupEncrypted(f, keys); err != nil {
		// Leaving the fragment behind is worse than having written nothing:
		// it has the name of a backup, and the next attempt refuses to
		// overwrite it.
		f.Close()
		if rErr := os.Remove(args[0]); rErr != nil {
			fmt.Fprintf(os.Stderr, "WARNING: could not remove the partial backup %s: %v\n",
				args[0], rErr)
		}
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(args[0])
		return errors.Wrapf(err, "failed to flush %s", args[0])
	}

	info, err := os.Stat(args[0])
	if err == nil {
		fmt.Printf("Wrote %s (%s)\n", args[0], utils.HumanBytes(info.Size()))
	}
	// Guidance goes to stderr so that redirecting stdout captures the result
	// and not the advice.
	fmt.Fprintln(os.Stderr, "This covers the catalog only. Keep the object data and "+
		"masterkey.json from the same store alongside it.")
	if pstoreKeyFile == "" {
		fmt.Fprintln(os.Stderr, "It is sealed to this origin's issuer keys. To be able to "+
			"restore it without them, save the key printed by `pelican-server origin pstore "+
			"metadata-backup-key`. To let someone restore only this one file, give them "+
			"`pelican-server origin pstore metadata-backup-key "+args[0]+"` instead.")
	}
	return nil
}

func runPStoreRestore(cmd *cobra.Command, args []string) error {
	store, err := openPStoreForCLI(cmd, true)
	if err != nil {
		return err
	}
	defer store.Close()

	f, err := os.Open(args[0])
	if err != nil {
		return errors.Wrapf(err, "cannot read %s", args[0])
	}
	defer f.Close()

	keys, err := pstoreBackupKeys()
	if err != nil {
		return err
	}
	// Restore decides from the file's own magic whether it is sealed and under
	// which format version, so an operator does not have to know which release
	// wrote the snapshot they are holding.
	if err := store.Restore(f, keys); err != nil {
		return err
	}
	fmt.Printf("Restored the catalog from %s.\n", args[0])
	fmt.Fprintln(os.Stderr, "The catalog is only half of a recovery: the object data and "+
		"masterkey.json from the same store must be in place too.")
	fmt.Fprintln(os.Stderr,
		"Verify with `pelican-server origin pstore fsck --deep` before starting the origin.")
	return nil
}

// pstoreBackupKeys resolves the keys a hand-run backup or restore uses.
//
// openPStoreForCLI has already loaded the origin's issuer keys -- the store
// itself cannot be opened without them -- so the default path needs no extra
// setup.  Each flag replaces the issuer keys rather than adding to them: an
// operator passing one either wants a backup that does not depend on this host,
// or is restoring on a host that has never had its keys.
//
// --file-key is checked first because it is the narrowest thing an operator can
// be holding: it opens the one archive it was printed for, so if it is present
// it is what they mean.
func pstoreBackupKeys() (pstore.BackupKeys, error) {
	if pstoreFileKeyFile != "" {
		key, err := pstoreReadKeyFile(pstoreFileKeyFile)
		if err != nil {
			return pstore.BackupKeys{}, err
		}
		return pstore.BackupKeys{FileKey: key}, nil
	}
	if pstoreKeyFile == "" {
		return pstore.BackupKeys{IssuerKeys: config.GetIssuerPrivateKeys()}, nil
	}
	key, err := pstoreReadKeyFile(pstoreKeyFile)
	if err != nil {
		return pstore.BackupKeys{}, err
	}
	return pstore.BackupKeys{BackupKey: key}, nil
}

// pstoreReadKeyFile loads one base64 key from a file.
func pstoreReadKeyFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot read the backup key from %s", path)
	}
	key, err := pstore.ParseBackupKey(string(data))
	if err != nil {
		return nil, errors.Wrapf(err, "cannot use the key in %s", path)
	}
	return key, nil
}

// pstoreEscrowBackupKey re-derives the level-2 backup private key for the
// origin's active issuer key.
//
// Split out from the command so it can be exercised without going through
// cobra and stdout: what matters about it is that it is reproducible.
func pstoreEscrowBackupKey() ([]byte, error) {
	issuerKey, err := config.GetIssuerPrivateJWK()
	if err != nil {
		return nil, errors.Wrap(err, "failed to load the origin's issuer key")
	}
	return pstore.DeriveBackupKey(issuerKey)
}

// pstoreFileBackupKey re-derives the level-3 key belonging to one backup file.
//
// Only the header is read, so the file may sit anywhere and be of any size.
// Whatever pstoreBackupKeys resolved -- the origin's issuer keys, or an escrowed
// backup key -- reaches the same answer, because the archive carries its own
// backup key sealed to both.
//
// Split out from the command for the same reason as pstoreEscrowBackupKey: the
// property worth testing is that the key it prints is the one that opens that
// file, which has nothing to do with cobra.
func pstoreFileBackupKey(path string) ([]byte, error) {
	keys, err := pstoreBackupKeys()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot read %s", path)
	}
	defer f.Close()
	key, err := pstore.DeriveFileKey(f, keys)
	return key, errors.Wrapf(err, "cannot derive the key for %s", path)
}

func runPStoreBackupKey(cmd *cobra.Command, args []string) error {
	if err := config.InitClient(); err != nil {
		return errors.Wrap(err, "failed to initialize configuration")
	}

	// The key alone goes to stdout so it can be redirected to a file; the
	// guidance goes to stderr so it does not end up in that file.
	if len(args) == 0 {
		key, err := pstoreEscrowBackupKey()
		if err != nil {
			return err
		}
		fmt.Println(pstore.FormatBackupKey(key))
		fmt.Fprintln(os.Stderr,
			"This is the BACKUP KEY: it opens every metadata backup this origin has "+
				"written. It is derived from this origin's issuer keys, so it is the same "+
				"every time it is printed. Keep it somewhere the metadata backups are not: "+
				"it is only needed if the issuer keys are lost, and alongside a backup it "+
				"exposes the store's namespace. To hand out one archive instead, print that "+
				"file's own key with `metadata-backup-key <file>`.")
		return nil
	}

	// Deriving a named file's key needs the whole keyring, not just the active
	// key: the archive may have been sealed before a rotation.  Loading it is
	// skipped entirely when an escrowed backup key is supplied, which is the
	// case where this host has no issuer keys to load.
	if pstoreKeyFile == "" {
		if _, err := config.GetIssuerPublicJWKS(); err != nil {
			return errors.Wrap(err, "failed to load the origin's issuer keys; pass "+
				"--key-file with the key from `metadata-backup-key` to derive this file's "+
				"key without them")
		}
	}
	key, err := pstoreFileBackupKey(args[0])
	if err != nil {
		return err
	}
	fmt.Println(pstore.FormatBackupKey(key))
	fmt.Fprintf(os.Stderr,
		"This is the key for %s ALONE -- NOT this origin's backup key. Every backup is "+
			"encrypted under a key of its own, derived from the backup key and the salt "+
			"stored in that file, so this one opens no other backup. Restore with "+
			"`pelican-server origin pstore metadata-restore --file-key <this key in a file> %s`.\n",
		args[0], args[0])
	return nil
}

func runPStoreExport(cmd *cobra.Command, args []string) error {
	if pstoreExportTo == "" {
		return errors.New("--to is required: it names the directory to write into")
	}
	store, err := openPStoreForCLI(cmd, false)
	if err != nil {
		return err
	}
	defer store.Close()

	report, err := store.Export(cmd.Context(), pstore.ExportOptions{
		Root:   pstorePathArg(args),
		Dest:   pstoreExportTo,
		Verify: pstoreVerify,
		DryRun: pstoreDryRun,
		Resume: pstoreResume,
	})
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if pstoreDryRun {
		fmt.Fprintf(w, "Would write:\t%d files, %d directories\n",
			report.FilesWritten, report.DirsCreated)
	} else {
		fmt.Fprintf(w, "Files written:\t%d\n", report.FilesWritten)
		fmt.Fprintf(w, "Directories:\t%d\n", report.DirsCreated)
	}
	if report.AlreadyPresent > 0 {
		fmt.Fprintf(w, "Already present:\t%d\n", report.AlreadyPresent)
	}
	fmt.Fprintf(w, "Bytes:\t%s\n", utils.HumanBytes(report.BytesWritten))
	w.Flush()

	if len(report.Failed) == 0 {
		return nil
	}

	fmt.Printf("\n%d object(s) could not be exported:\n", len(report.Failed))
	paths := make([]string, 0, len(report.Failed))
	for p := range report.Failed {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		fmt.Printf("  %s: %s\n", p, report.Failed[p])
	}
	// Non-zero so a recovery script notices rather than assuming success.
	return errors.Errorf("%d object(s) could not be exported", len(report.Failed))
}
