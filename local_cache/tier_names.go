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

package local_cache

import (
	"context"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/utils"
)

// The names view is a tree of hard links, beside a shared-filesystem
// target's hash-keyed objects, that spells each object by its federation
// path:
//
//	names/<namespace path>@<etag>  = objects/aa/bb/<instance hash>
//	names/<namespace path>         = the same file, for the current version
//
// The first kind names one version of an object; the second -- the bare name
// -- is whichever version the cache currently considers the latest.
// It exists so that someone with read access to the shared filesystem (a
// user who prestaged their favourite dataset, say) can open the objects by
// their logical names, read-only, without going through Pelican at all.
//
// Names are hard links rather than symlinks so that the view behaves as the
// plain files its readers take it for: copying a directory of it copies the
// data, not links that dangle outside the tree; a container that mounts only
// part of it can still read it; and tools that do not follow links (rsync,
// tar, find -type f) see files.  A hard link has nothing to read back, so
// the view tells which object a name is by its inode: the sweep lists the
// objects tree first and looks each name's inode up in that listing.  An
// object's file is never rewritten in place -- a new copy is a new file
// renamed over the key -- so an inode stands for one object for as long as
// the file exists.  The price is that a name the cache failed to remove (a
// crash between removing an object's metadata and its names, say) keeps the
// object's bytes on disk after the object is deleted, until the sweep finds
// the name linked to no object and removes it.  The view needs a filesystem
// that supports hard links; a target on one that does not is refused unless
// its view is disabled.
//
// Links are replaced atomically: a new one is created under a temporary name
// and renamed over the old, so a reader opening the bare name gets either
// the previous version or the new one, never a missing file.
//
// The cache's metadata is the source of truth.  Links are added when an
// object is tiered, withdrawn when it is evicted or deleted, and the bare
// name moves as soon as the cache learns of a newer version (withdrawn if
// that version is not on the target).  The hourly consistency sweep
// re-derives the whole tree, removing anything stale or foreign and
// restoring anything missing, so a crash between a metadata change and the
// matching link change heals on its own.  Nothing is published while the
// target fails its liveness probe, since the probe is what notices that
// someone else could be reshaping the tree.
//
// Encoding.  The tree must map names to links injectively, and '@' is both
// the version separator and a legal character in an object's name: an
// object named "a@b" would otherwise collide with version "b" of object "a".
// So every path component and the entity tag are percent-encoded for the
// bytes that cannot appear verbatim -- '%' itself (so the encoding is
// reversible), '@', '/', '"', and control characters -- and a raw '@' in a
// link name can only ever be the separator.  Percent-encoding was chosen
// because it is what these names look like in a URL already, so a reader
// can decode it without being told the scheme, and it leaves ordinary names
// untouched.  A strong entity tag's surrounding quotes are dropped, since
// every strong tag has them and a quote in a file name is a trap in a shell.
// Names longer than a file name may be (255 bytes) are left out of the view,
// as are paths that are not in canonical form ("/a//b", "/a/./b"), which
// would otherwise share a link with their canonical spelling.
//
// Some filesystems fold names: case-insensitive ones (a ZFS dataset with
// casesensitivity=insensitive, mixed-protocol NAS volumes, macOS's default
// APFS) treat "Data.bin" and "data.bin" as one entry, and normalizing ones
// treat composed and decomposed Unicode as one.  There, two objects could
// share a link and a reader asking for one would get the other's bytes.  The
// view probes for folding when the target opens, and on a folding
// filesystem it also escapes upper-case ASCII letters and every non-ASCII
// byte.  What remains -- lower-case letters, digits, punctuation, and
// escapes whose hex digits are only ever compared case-insensitively -- is
// unchanged by folding, so the mapping stays injective; the cost is that
// such names are harder to read, which beats serving the wrong object.
//
// Exact names.  With NamesView: exact the tree instead spells each object
// exactly as its federation path does, with no escaping and no versions:
//
//	names/<namespace path>  = objects/aa/bb/<instance hash>
//
// for the version the cache currently considers the latest, and nothing for
// any other.  Without versions in the tree, '@' and '%' mean nothing to it,
// so names are left as they are; the mapping is the identity on paths, and
// injective for that reason alone.  It cannot survive a filesystem that
// folds names, where two objects would share a link, so a target asking for
// exact names on one is refused when it opens.  Names that cannot be spelled
// at all -- a NUL byte, a component longer than 255 bytes -- are left out.

// tierNameMaxComponent is the longest file name the view will create; POSIX
// filesystems commonly refuse anything longer.
const tierNameMaxComponent = 255

// escapeTierName percent-encodes the bytes a names-view file name must not
// carry verbatim; foldSafe adds those a name-folding filesystem would
// conflate.  See the encoding note above.
func escapeTierName(s string, foldSafe bool) string {
	if s == "." || s == ".." {
		return strings.ReplaceAll(s, ".", "%2E")
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '%' || c == '@' || c == '/' || c == '"' || c < 0x20 || c == 0x7f,
			foldSafe && (c >= 'A' && c <= 'Z' || c >= 0x80):
			fmt.Fprintf(&sb, "%%%02X", c)
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// tierNameETag spells an entity tag for a link name: a strong tag loses its
// quotes, then the result is escaped.  A weak tag keeps its W/ prefix (with
// the slash escaped), so it cannot collide with the strong tag of the same
// value.
func tierNameETag(etag string, foldSafe bool) string {
	if len(etag) >= 2 && etag[0] == '"' && etag[len(etag)-1] == '"' {
		etag = etag[1 : len(etag)-1]
	}
	return escapeTierName(etag, foldSafe)
}

// tierLogicalName is where one version of an object appears in the view.
// All fields are already escaped.
type tierLogicalName struct {
	dir  string // the link's directory relative to the root ("names/ns/sub")
	base string // the object's final path component
	tag  string // the entity tag
}

// newTierLogicalName works out where an object version belongs in the view,
// reporting false for an object that cannot be named: no source URL, a path
// not in canonical form, or a name too long for the filesystem.
func newTierLogicalName(sourceURL, etag string, foldSafe bool) (tierLogicalName, bool) {
	parts, ok := tierNameParts(sourceURL)
	if !ok {
		return tierLogicalName{}, false
	}
	for i, part := range parts {
		parts[i] = escapeTierName(part, foldSafe)
		if len(parts[i]) > tierNameMaxComponent {
			return tierLogicalName{}, false
		}
	}
	n := tierLogicalName{
		dir:  path.Join(append([]string{posixNamesDir}, parts[:len(parts)-1]...)...),
		base: parts[len(parts)-1],
		tag:  tierNameETag(etag, foldSafe),
	}
	if len(n.versionFile()) > tierNameMaxComponent {
		return tierLogicalName{}, false
	}
	return n, true
}

// tierNameParts splits an object's federation path into the components the
// view spells, reporting false for one it cannot name: no source URL, a path
// not in canonical form, or one with an encoded slash, which would decode
// into a path another object may already have.
func tierNameParts(sourceURL string) ([]string, bool) {
	if sourceURL == "" {
		return nil, false
	}
	u, err := url.Parse(sourceURL)
	if err != nil || u.Path == "" || u.Path == "/" || !strings.HasPrefix(u.Path, "/") || path.Clean(u.Path) != u.Path {
		return nil, false
	}
	if strings.Contains(strings.ToUpper(u.RawPath), "%2F") {
		return nil, false
	}
	return strings.Split(strings.TrimPrefix(u.Path, "/"), "/"), true
}

// newTierExactName works out where an object belongs in an exact-names view
// (see the note above): its federation path, unchanged.
func newTierExactName(sourceURL string) (tierLogicalName, bool) {
	parts, ok := tierNameParts(sourceURL)
	if !ok {
		return tierLogicalName{}, false
	}
	for _, part := range parts {
		if len(part) > tierNameMaxComponent || strings.IndexByte(part, 0) >= 0 {
			return tierLogicalName{}, false
		}
	}
	return tierLogicalName{
		dir:  path.Join(append([]string{posixNamesDir}, parts[:len(parts)-1]...)...),
		base: parts[len(parts)-1],
	}, true
}

// versionFile is the file name of the version link.
func (n tierLogicalName) versionFile() string { return n.base + "@" + n.tag }

// versionPath is the version link's path relative to the root.
func (n tierLogicalName) versionPath() string { return n.dir + "/" + n.versionFile() }

// currentPath is the bare name's path relative to the root.
func (n tierLogicalName) currentPath() string { return n.dir + "/" + n.base }

// tierFileID identifies a file on the target by device and inode: what every
// hard link to it shares.
type tierFileID struct{ dev, ino uint64 }

func tierFileIDOf(info fs.FileInfo) (tierFileID, bool) {
	dev, ino, ok := utils.FileVFSID(info)
	return tierFileID{dev: dev, ino: ino}, ok
}

// tierInodeIndex maps the files of a target's objects tree to the objects
// they hold, as of one listing, sorted by file.  The sweep keeps one entry
// per object on the target, and a sorted slice costs about half what a map
// would.
type tierInodeIndex []tierInodeEntry

type tierInodeEntry struct {
	id   tierFileID
	hash [32]byte
}

// lookup returns the object whose file is id, or "" if the listing had none.
func (x tierInodeIndex) lookup(id tierFileID) InstanceHash {
	i := sort.Search(len(x), func(i int) bool {
		e := x[i].id
		return e.dev > id.dev || e.dev == id.dev && e.ino >= id.ino
	})
	if i < len(x) && x[i].id == id {
		return InstanceHash(hex.EncodeToString(x[i].hash[:]))
	}
	return ""
}

// buildTierInodeIndex lists a target's objects tree.
func buildTierInodeIndex(ctx context.Context, target *tierTarget) (tierInodeIndex, error) {
	var x tierInodeIndex
	err := target.names.b.listObjects(ctx, func(key string, info fs.FileInfo) error {
		hash := target.hashFromKey(key)
		id, ok := tierFileIDOf(info)
		if hash == "" || !ok {
			return nil // the identity or probe object, or a platform without inodes
		}
		e := tierInodeEntry{id: id}
		if n, err := hex.Decode(e.hash[:], []byte(hash)); err != nil || n != len(e.hash) {
			return nil
		}
		x = append(x, e)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(x, func(i, j int) bool {
		a, b := x[i].id, x[j].id
		return a.dev < b.dev || a.dev == b.dev && a.ino < b.ino
	})
	return x, nil
}

// tierObjectFile is an object's file on the target, as the names view links
// to it.
type tierObjectFile struct {
	hash InstanceHash
	path string      // relative to the root
	info fs.FileInfo // its lstat, to recognize links to it
}

// tierNameView maintains the names tree of one shared-filesystem target.
// Its methods do filesystem work only; deciding what belongs in the tree is
// the StorageManager's job (publishTierName and friends), which holds mu
// across the metadata check and the link change so that the two cannot be
// interleaved with an eviction.
type tierNameView struct {
	b *posixTierBackend
	// enabled is false when the operator set NamesView: none.  The tree is
	// then emptied by the next sweep rather than left to rot.
	enabled bool
	// foldSafe is set when the filesystem folds names; see the note above.
	foldSafe bool
	// exact is set for NamesView: exact; see the note above.
	exact bool
	mu    sync.Mutex
	// While a sweep runs, index is its listing of the objects tree, and
	// linked records every link made since the listing began, which the
	// listing may have missed: together they say whose a name is.  Both are
	// guarded by mu and nil outside a sweep.
	index  tierInodeIndex
	linked map[tierFileID]InstanceHash
}

// newTierNameView prepares the names view of a shared-filesystem target.  It
// fails for a filesystem that cannot hold the view: one without hard links,
// or, for an exact-names view, one that folds names (or that cannot be
// checked), which could not keep two objects apart.
func newTierNameView(b *posixTierBackend, enabled, exact bool) (*tierNameView, error) {
	v := &tierNameView{b: b, enabled: enabled, exact: exact}
	if enabled {
		if err := tierHardLinkProbe(b); err != nil {
			return nil, errors.Wrapf(err, "cache tier target %s: its names view is made of hard links, which the "+
				"filesystem would not create; set NamesView: none to use the target without one", b.display)
		}
	}
	folds, err := tierNameFoldingProbe(b)
	if err != nil && enabled && exact {
		return nil, errors.Wrapf(err, "cache tier target %s: could not check whether the filesystem folds file "+
			"names, which NamesView: exact needs to know", b.display)
	}
	if err != nil {
		// Assume the worst: the cost is only less readable names.
		log.Warnf("Could not tell whether cache tier target %s folds file names (%v); spelling its names view "+
			"so that folding cannot conflate two objects", b.display, err)
		folds = true
	}
	if folds && enabled && exact {
		return nil, errors.Errorf("cache tier target %s is on a filesystem that treats names differing in case or "+
			"Unicode normalization as the same, where NamesView: exact could give two objects one name; use the "+
			"default names view, which escapes such names", b.display)
	}
	if folds && enabled {
		log.Warnf("Cache tier target %s is on a filesystem that treats names differing in case or Unicode "+
			"normalization as the same; its names view escapes upper-case and non-ASCII characters so that no "+
			"two objects share a name", b.display)
	}
	v.foldSafe = folds
	return v, nil
}

// tierNameFoldingProbe is probeNameFolding; tests replace it to run on a
// filesystem other than the one they are given.
var tierNameFoldingProbe = probeNameFolding

// The names the folding probe creates and looks for.  They are spelled with
// escapes rather than as the characters themselves: a tool that normalizes
// Unicode would otherwise turn the decomposed spelling into the precomposed
// one, and the probe would then find every filesystem folding names.
const (
	foldProbeCreated    = "-X\u00e9"  // "é" precomposed (NFC)
	foldProbeOtherCase  = "-x\u00e9"  // the same name in another case
	foldProbeDecomposed = "-Xe\u0301" // the same name decomposed (NFD)
)

// probeNameFolding reports whether the filesystem treats names that differ
// in ASCII case, or in Unicode normalization, as the same entry.
func probeNameFolding(b *posixTierBackend) (bool, error) {
	tmp, release := b.newTempName("fold")
	defer release()
	created := tmp + foldProbeCreated
	f, err := b.fs.OpenFile(created, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false, err
	}
	_ = f.Close()
	defer func() { _ = b.fs.Remove(created) }()
	for _, variant := range []string{tmp + foldProbeOtherCase, tmp + foldProbeDecomposed} {
		if _, err := b.fs.Lstat(variant); err == nil {
			return true, nil
		} else if !errors.Is(err, fs.ErrNotExist) {
			return false, err
		}
	}
	return false, nil
}

// tierHardLinkProbe is probeHardLinks; tests replace it to stand in for a
// filesystem without hard links.
var tierHardLinkProbe = probeHardLinks

// probeHardLinks checks that the filesystem lets the cache hard-link a file
// of its own.
func probeHardLinks(b *posixTierBackend) error {
	tmp, release := b.newTempName("hardlink")
	defer release()
	f, err := b.fs.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_ = f.Close()
	defer func() { _ = b.fs.Remove(tmp) }()
	linked := tmp + "-link"
	if err := b.fs.Link(tmp, linked); err != nil {
		return err
	}
	return b.fs.Remove(linked)
}

// logicalName is where the object's version belongs in this view's spelling.
func (v *tierNameView) logicalName(sourceURL, etag string) (tierLogicalName, bool) {
	if v.exact {
		return newTierExactName(sourceURL)
	}
	return newTierLogicalName(sourceURL, etag, v.foldSafe)
}

// objectLinkPath is the name that leads to the object whatever version is
// current: in an exact view, the object's own name; otherwise, its version
// name.
func (v *tierNameView) objectLinkPath(n tierLogicalName) string {
	if v.exact {
		return n.currentPath()
	}
	return n.versionPath()
}

// objectFile finds the file of the object stored under key.
func (v *tierNameView) objectFile(hash InstanceHash, key string) (tierObjectFile, error) {
	objectPath, err := v.b.objectPath(key)
	if err != nil {
		return tierObjectFile{}, err
	}
	info, err := v.b.fs.Lstat(objectPath)
	if err != nil {
		return tierObjectFile{}, err
	}
	return tierObjectFile{hash: hash, path: objectPath, info: info}, nil
}

// ownerLocked returns the object whose file info is, as far as the running
// sweep can tell, or "" -- always "" outside a sweep.
func (v *tierNameView) ownerLocked(info fs.FileInfo) InstanceHash {
	id, ok := tierFileIDOf(info)
	if !ok {
		return ""
	}
	if hash, ok := v.linked[id]; ok {
		return hash
	}
	return v.index.lookup(id)
}

// placeLink makes name a hard link to obj, atomically replacing whatever was
// there.
func (v *tierNameView) placeLink(name string, obj tierObjectFile) error {
	tmp, release := v.b.newTempName("link")
	defer release()
	if err := v.b.fs.Link(obj.path, tmp); err != nil {
		return errors.Wrapf(err, "failed to create a link for %s", name)
	}
	// rename(2) over an existing name replaces it in one step; over a
	// directory (an object whose name is also another object's directory)
	// it fails, and the view simply lacks that name.  Over another link to
	// the same file it succeeds without doing anything, leaving tmp behind;
	// so tmp is removed whatever happened.
	err := v.b.fs.Rename(tmp, name)
	_ = v.b.fs.Remove(tmp)
	if err != nil {
		return errors.Wrapf(err, "failed to place the link %s", name)
	}
	if id, ok := tierFileIDOf(obj.info); ok && v.linked != nil {
		v.linked[id] = obj.hash
	}
	return nil
}

// removeLinkIf removes name if it is a link to obj.  Checking keeps a stale
// removal from deleting a name that has since been given to another file.
func (v *tierNameView) removeLinkIf(name string, obj tierObjectFile) (bool, error) {
	info, err := v.b.fs.Lstat(name)
	if err != nil || !os.SameFile(info, obj.info) {
		return false, nil
	}
	if err := v.b.fs.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, errors.Wrapf(err, "failed to remove the link %s", name)
	}
	return true, nil
}

// pruneDirs removes dir and then each parent up to the names tree's root,
// stopping at the first that is not empty.
func (v *tierNameView) pruneDirs(dir string) {
	for dir != posixNamesDir && strings.HasPrefix(dir, posixNamesDir+"/") {
		if err := v.b.fs.Remove(dir); err != nil {
			return
		}
		dir = path.Dir(dir)
	}
}

// unlink withdraws one version of an object: its version name, and the bare
// name if that is the same file.
func (v *tierNameView) unlink(n tierLogicalName, hash InstanceHash, key string) error {
	obj, err := v.objectFile(hash, key)
	if errors.Is(err, fs.ErrNotExist) {
		// Its names, if any are left, are linked to no object now; the
		// sweep removes those.
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := v.removeLinkIf(v.objectLinkPath(n), obj); err != nil {
		return err
	}
	if !v.exact {
		if _, err := v.removeLinkIf(n.currentPath(), obj); err != nil {
			return err
		}
	}
	v.pruneDirs(n.dir)
	return nil
}

// publishTierName adds a just-tiered object to its target's names view, or
// brings its links up to date.  Failures are logged, never returned: the
// view is a convenience, and the sweep retries whatever this misses.
func (sm *StorageManager) publishTierName(target *tierTarget, hash InstanceHash) {
	v := target.names
	if v == nil || !v.enabled || !target.healthy.Load() {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, err := sm.publishTierNameLocked(target, hash); err != nil {
		log.Debugf("Could not add %s to the names view of %s: %v", hash, target.DisplayURL(), err)
	}
}

// publishTierNameLocked brings one object's links in line with its
// metadata.  The metadata is re-read here, under the view's lock, rather
// than trusted from the caller: an eviction that removed the object a
// moment ago has already withdrawn its links, and must not see them
// re-created behind it.
func (sm *StorageManager) publishTierNameLocked(target *tierTarget, hash InstanceHash) (int, error) {
	v := target.names
	meta, err := sm.db.GetMetadata(hash)
	if err != nil {
		return 0, err
	}
	if meta == nil || meta.StorageID != target.id || meta.Completed.IsZero() {
		return 0, nil
	}
	name, ok := v.logicalName(meta.SourceURL, meta.ETag)
	if !ok {
		return 0, nil
	}
	key := target.objectKey(hash)
	if allowed, known := target.mayHold(meta.SourceURL); !allowed {
		if known {
			return 0, v.unlink(name, hash, key)
		}
		return 0, nil
	}
	obj, err := v.objectFile(hash, key)
	if err != nil {
		return 0, err
	}
	current, err := sm.isLatest(meta)
	if err != nil {
		return 0, err
	}
	if v.exact {
		return sm.publishExactNameLocked(target, name, obj, current)
	}

	if err := v.b.mkdirAll(name.dir); err != nil {
		return 0, err
	}
	changed := 0
	placed, err := sm.placeNameLocked(target, name.versionPath(), obj)
	if err != nil {
		return 0, err
	}
	if placed {
		changed++
	}
	if current {
		placed, err := sm.placeNameLocked(target, name.currentPath(), obj)
		if placed {
			changed++
		}
		return changed, err
	}
	removed, err := v.removeLinkIf(name.currentPath(), obj)
	if removed {
		changed++
	}
	return changed, err
}

// publishExactNameLocked is publishTierNameLocked for an exact-names view:
// the object's name is a link to it while it is the current version, and is
// not once it is not.
func (sm *StorageManager) publishExactNameLocked(target *tierTarget, name tierLogicalName, obj tierObjectFile, current bool) (int, error) {
	v := target.names
	if !current {
		removed, err := v.removeLinkIf(name.currentPath(), obj)
		if removed {
			v.pruneDirs(name.dir)
			return 1, err
		}
		return 0, err
	}
	if err := v.b.mkdirAll(name.dir); err != nil {
		return 0, err
	}
	placed, err := sm.placeNameLocked(target, name.currentPath(), obj)
	if placed {
		return 1, err
	}
	return 0, err
}

// placeNameLocked makes name a link to obj, unless it is one already or
// another object rightly holds it: two versions whose tags differ only in
// quoting, say, or one path in two federations.  The first keeps it;
// flipping between them every sweep would be worse than either.  Only a
// sweep can tell whose a name is; outside one, the newer link wins until the
// next sweep, which then keeps it.
func (sm *StorageManager) placeNameLocked(target *tierTarget, name string, obj tierObjectFile) (bool, error) {
	v := target.names
	if info, err := v.b.fs.Lstat(name); err == nil {
		if os.SameFile(info, obj.info) {
			return false, nil
		}
		if owner := v.ownerLocked(info); owner != "" && owner != obj.hash &&
			sm.judgeName(target, name, owner).verdict == linkKeep {
			return false, errors.Errorf("%s already names another object", name)
		}
	}
	if err := v.placeLink(name, obj); err != nil {
		return false, err
	}
	return true, nil
}

// unpublishTierName withdraws an object from its target's names view.
// Callers remove the metadata first and the object last, so the names never
// outlive the file they are links to.
func (sm *StorageManager) unpublishTierName(target *tierTarget, hash InstanceHash, sourceURL, etag string) {
	v := target.names
	if v == nil {
		return
	}
	name, ok := v.logicalName(sourceURL, etag)
	if !ok {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.unlink(name, hash, target.objectKey(hash)); err != nil {
		log.Warnf("Failed to remove %s from the names view of %s (the consistency sweep will retry): %v",
			hash, target.DisplayURL(), err)
	}
}

// onLatestETagChanged moves an object's bare name when the cache learns of
// a newer version, rather than leaving it on the superseded one until the
// next sweep: to the new version if that is on a shared-filesystem target,
// and otherwise away entirely, so that nobody reading the bare name gets
// bytes the origin has replaced.  It runs on the request that learned of
// the change, so it touches the filesystem only for objects in a view.
func (sm *StorageManager) onLatestETagChanged(objectHash ObjectHash, oldETag, newETag string) {
	for _, etag := range []string{oldETag, newETag} {
		hash := sm.db.InstanceHash(etag, objectHash)
		meta, err := sm.db.GetMetadata(hash)
		if err != nil || meta == nil {
			continue
		}
		if target := sm.getTierTarget(meta.StorageID); target != nil && target.names != nil {
			// publishTierName re-reads the latest version itself, so the
			// order these notifications arrive in does not matter.
			sm.publishTierName(target, hash)
		}
	}
}

// linkVerdict is the sweep's judgement of one entry in the names tree.
type linkVerdict int

const (
	linkKeep   linkVerdict = iota // valid, or undecidable right now
	linkRemove                    // stale or foreign
)

// tierNameRole is what a valid name is to its object.
type tierNameRole int

const (
	// tierNameObject is the name the object has whether or not it is the
	// current version: its version name, or in an exact view its only one.
	tierNameObject tierNameRole = iota + 1 // zero: kept, but undecidable right now
	// tierNameCurrent is the bare name of the current version in a
	// versioned view.
	tierNameCurrent
)

// tierNameJudgement is judgeName's verdict on one name.
type tierNameJudgement struct {
	verdict linkVerdict
	role    tierNameRole // for a name kept
	current bool         // the object is the current version
}

// judgeName decides whether linkPath, a link to the object hash, belongs in
// the view, and if so what it is to the object.  hash is "" for a file that
// is no known object's.
func (sm *StorageManager) judgeName(target *tierTarget, linkPath string, hash InstanceHash) tierNameJudgement {
	remove := tierNameJudgement{verdict: linkRemove}
	undecided := tierNameJudgement{verdict: linkKeep}
	v := target.names
	if !v.enabled || hash == "" {
		return remove
	}
	meta, err := sm.db.GetMetadata(hash)
	if err != nil {
		return undecided // cannot tell; do not destroy on a read error
	}
	if meta == nil || meta.StorageID != target.id || meta.Completed.IsZero() {
		return remove
	}
	if allowed, known := target.mayHold(meta.SourceURL); known && !allowed {
		return remove
	}
	name, ok := v.logicalName(meta.SourceURL, meta.ETag)
	if !ok {
		return remove
	}
	current, err := sm.isLatest(meta)
	if err != nil {
		return undecided
	}
	switch {
	case linkPath == v.objectLinkPath(name) && (current || !v.exact):
		return tierNameJudgement{verdict: linkKeep, role: tierNameObject, current: current}
	case !v.exact && current && linkPath == name.currentPath():
		return tierNameJudgement{verdict: linkKeep, role: tierNameCurrent, current: true}
	}
	return remove
}

// isLatest reports whether meta is the version the cache considers current.
func (sm *StorageManager) isLatest(meta *CacheMetadata) (bool, error) {
	latest, found, err := sm.db.GetLatestETag(sm.db.ObjectHash(meta.SourceURL))
	if err != nil {
		return false, err
	}
	return found && latest == meta.ETag, nil
}

// stillRemovableLocked re-judges, under the view's lock and right before a
// removal, an entry the sweep found stale: it must still be the file the
// sweep looked at, and still not belong, so that nothing changed since the
// sweep looked is lost.
func (sm *StorageManager) stillRemovableLocked(target *tierTarget, name string, seen fs.FileInfo) bool {
	v := target.names
	info, err := v.b.fs.Lstat(name)
	if err != nil || !os.SameFile(info, seen) {
		return false
	}
	if !info.Mode().IsRegular() {
		return true // the view holds only links to objects
	}
	return sm.judgeName(target, name, v.ownerLocked(info)).verdict == linkRemove
}

// tierNamesPage bounds how many objects the sweep collects from one
// metadata scan before releasing the database to work on them.
const tierNamesPage = 1000

// errTierNamesPageFull stops a metadata scan once a page is collected.
var errTierNamesPageFull = errors.New("page full")

// hashSet is a compact set of instance hashes: the raw digest bytes, about
// a third of the size of the hex strings, since the sweep keeps one entry
// per object on the target.
type hashSet map[[32]byte]struct{}

func (s hashSet) add(h InstanceHash) {
	var k [32]byte
	if n, err := hex.Decode(k[:], []byte(h)); err == nil && n == len(k) {
		s[k] = struct{}{}
	}
}

func (s hashSet) has(h InstanceHash) bool {
	var k [32]byte
	if n, err := hex.Decode(k[:], []byte(h)); err != nil || n != len(k) {
		return false
	}
	_, ok := s[k]
	return ok
}

// reconcileTierNames rebuilds a target's names view from the metadata.
//
// It lists the objects tree, to learn which file is which object; walks the
// names tree once, judging each name against the metadata store -- a
// database lookup, not a filesystem round trip -- removing whatever is stale,
// foreign or linked to no object, and remembering which objects have a valid
// name; and then publishes only the objects the walk did not see.  In the
// steady state that is one lstat per object and per name, and nothing else on
// the filesystem.  The view's lock is taken only around changes, each
// re-checked under it, so evictions are never held up behind the sweep's
// reads.
//
// The listing comes first, so a name seen by the walk whose file the listing
// did not have was not linked to any object when the listing ran -- unless
// the cache linked it since, which the view records while a sweep runs.
//
// Nothing happens while the target is failing its liveness probe.
func (cc *ConsistencyChecker) reconcileTierNames(ctx context.Context, target *tierTarget) (added, removed int, err error) {
	v := target.names
	if v == nil {
		return 0, 0, nil
	}
	if !target.healthy.Load() {
		log.Debugf("Not reconciling the names view of %s while it fails its liveness probe", target.DisplayURL())
		return 0, 0, nil
	}
	start := time.Now()
	defer func() {
		tierNamesSweepDuration.WithLabelValues(target.metricLabel()).Set(time.Since(start).Seconds())
	}()

	var index tierInodeIndex
	if v.enabled {
		v.mu.Lock()
		v.linked = map[tierFileID]InstanceHash{}
		v.mu.Unlock()
		defer func() {
			v.mu.Lock()
			v.index, v.linked = nil, nil
			v.mu.Unlock()
		}()
		if index, err = buildTierInodeIndex(ctx, target); err != nil {
			return 0, 0, err
		}
		v.mu.Lock()
		v.index = index
		v.mu.Unlock()
	}

	seen := hashSet{}
	added, removed, err = cc.walkTierNames(ctx, target, posixNamesDir, index, seen)
	if err != nil || !v.enabled {
		return added, removed, err
	}

	sm := cc.storage
	var after InstanceHash
	for {
		var page []InstanceHash
		scanErr := cc.db.ScanMetadataFrom(after, func(hash InstanceHash, meta *CacheMetadata) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if meta.StorageID != target.id || seen.has(hash) {
				return nil
			}
			if v.exact {
				// Only the current version has a name; any link to another
				// was judged by the walk.
				if current, err := sm.isLatest(meta); err == nil && !current {
					return nil
				}
			}
			page = append(page, hash)
			if len(page) >= tierNamesPage {
				after = hash
				return errTierNamesPageFull
			}
			return nil
		})
		if scanErr != nil && !errors.Is(scanErr, errTierNamesPageFull) {
			return added, removed, scanErr
		}
		for _, hash := range page {
			v.mu.Lock()
			n, linkErr := sm.publishTierNameLocked(target, hash)
			v.mu.Unlock()
			added += n
			if linkErr != nil {
				log.Debugf("Could not add %s to the names view of %s: %v", hash, target.DisplayURL(), linkErr)
			}
		}
		if scanErr == nil {
			return added, removed, nil
		}
	}
}

// walkTierNames reconciles one directory of the names tree and everything
// below it; see reconcileTierNames.
func (cc *ConsistencyChecker) walkTierNames(ctx context.Context, target *tierTarget, dir string, index tierInodeIndex, seen hashSet) (added, removed int, err error) {
	v := target.names
	sm := cc.storage
	entries, err := v.b.fs.ReadDirInfo(dir)
	if err != nil {
		return 0, 0, errors.Wrapf(err, "failed to list %s on cache tier target %s", dir, target.DisplayURL())
	}

	// removeIf takes the lock and removes name only if it still deserves it.
	removeIf := func(name string, info fs.FileInfo) {
		v.mu.Lock()
		defer v.mu.Unlock()
		if sm.stillRemovableLocked(target, name, info) {
			if err := v.b.fs.Remove(name); err == nil {
				removed++
			}
		}
	}

	wantCurrent := map[string]InstanceHash{}  // bare name -> the current version, which should hold it
	holdsCurrent := map[string]InstanceHash{} // bare name -> the current version it validly holds
	staleBare := map[string]fs.FileInfo{}     // bare names that do not belong as they are
	for _, info := range entries {
		if err := ctx.Err(); err != nil {
			return added, removed, err
		}
		name := dir + "/" + info.Name()
		switch {
		case info.IsDir():
			a, r, err := cc.walkTierNames(ctx, target, name, index, seen)
			added += a
			removed += r
			if err != nil {
				return added, removed, err
			}
			v.mu.Lock()
			_ = v.b.fs.Remove(name) // fails, harmlessly, unless empty
			v.mu.Unlock()
		case !info.Mode().IsRegular():
			// The cache only ever puts links to objects and directories
			// here, and the tree is writable only by the cache, so this was
			// put here by someone with the cache's privileges.  It is not
			// the cache's to keep.
			log.Warnf("Removing unexpected entry %s from the names view of %s", name, target.DisplayURL())
			removeIf(name, info)
		default:
			var hash InstanceHash
			if id, ok := tierFileIDOf(info); ok {
				hash = index.lookup(id)
			}
			j := sm.judgeName(target, name, hash)
			switch {
			case j.verdict == linkRemove && !v.exact && !strings.Contains(info.Name(), "@"):
				// A bare name: it may only need to move to the current
				// version, which replaces it in one step; decided below,
				// once the versions are known.
				staleBare[info.Name()] = info
			case j.verdict == linkRemove:
				removeIf(name, info)
			case j.role == tierNameObject:
				seen.add(hash)
				if !v.exact && j.current {
					base, _, _ := strings.Cut(info.Name(), "@")
					wantCurrent[base] = hash
				}
			case j.role == tierNameCurrent:
				holdsCurrent[info.Name()] = hash
			}
		}
	}

	// A current version whose bare name is missing, or held by another
	// version: point it at the current one.
	for base, hash := range wantCurrent {
		if holdsCurrent[base] == hash {
			continue
		}
		delete(staleBare, base)
		v.mu.Lock()
		n, err := sm.publishTierNameLocked(target, hash)
		v.mu.Unlock()
		added += n
		if err != nil {
			log.Debugf("Could not update %s in the names view of %s: %v", dir+"/"+base, target.DisplayURL(), err)
		}
	}
	// A bare name with no current version to point at.
	for file, info := range staleBare {
		removeIf(dir+"/"+file, info)
	}
	return added, removed, nil
}
