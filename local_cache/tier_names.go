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
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// The names view is a tree of symlinks, beside a shared-filesystem target's
// hash-keyed objects, that spells each object by its federation path:
//
//	names/<namespace path>@<etag>  -> ../../objects/aa/bb/<instance hash>
//	names/<namespace path>         -> <final component>@<etag>
//
// The first kind names one version of an object; the second -- the bare name
// -- resolves to whichever version the cache currently considers the latest.
// It exists so that someone with read access to the shared filesystem (a
// user who prestaged their favourite dataset, say) can open the objects by
// their logical names, read-only, without going through Pelican at all.
//
// Every link is relative.  An absolute link would bake in the cache's mount
// point, which clients may mount elsewhere, and os.Root -- what the Pelican
// client and other careful readers confine themselves with -- refuses to
// follow an absolute symlink even when its target is inside the root.
//
// Links are replaced atomically: a new one is created under a temporary name
// and renamed over the old, so a reader resolving the bare name sees either
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
//	names/<namespace path>  -> ../../objects/aa/bb/<instance hash>
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

// objectLinkFrom is what a link in dir must hold to reach the object at
// objectPath (relative to the root): one "../" per directory level.
func objectLinkFrom(dir, objectPath string) string {
	return strings.Repeat("../", strings.Count(dir, "/")+1) + objectPath
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
}

// newTierNameView prepares the names view of a shared-filesystem target.  It
// fails only for an exact-names view on a filesystem that folds names (or
// one that cannot be checked), which could not keep two objects apart.
func newTierNameView(b *posixTierBackend, enabled, exact bool) (*tierNameView, error) {
	v := &tierNameView{b: b, enabled: enabled, exact: exact}
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

// probeNameFolding reports whether the filesystem treats names that differ
// in ASCII case, or in Unicode normalization, as the same entry.
func probeNameFolding(b *posixTierBackend) (bool, error) {
	tmp, release := b.newTempName("fold")
	defer release()
	created := tmp + "-Xé" // "é" precomposed (NFC)
	f, err := b.fs.OpenFile(created, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false, err
	}
	_ = f.Close()
	defer func() { _ = b.fs.Remove(created) }()
	for _, variant := range []string{tmp + "-xé", tmp + "-Xé"} {
		if _, err := b.fs.Lstat(variant); err == nil {
			return true, nil
		} else if !errors.Is(err, fs.ErrNotExist) {
			return false, err
		}
	}
	return false, nil
}

// logicalName is where the object's version belongs in this view's spelling.
func (v *tierNameView) logicalName(sourceURL, etag string) (tierLogicalName, bool) {
	if v.exact {
		return newTierExactName(sourceURL)
	}
	return newTierLogicalName(sourceURL, etag, v.foldSafe)
}

// objectLinkPath is the link that leads to the object itself: in an exact
// view, the object's own name; otherwise, its version link.
func (v *tierNameView) objectLinkPath(n tierLogicalName) string {
	if v.exact {
		return n.currentPath()
	}
	return n.versionPath()
}

// placeLink makes name a symlink holding target, atomically replacing
// whatever link was there.  Reports whether anything changed.
func (v *tierNameView) placeLink(name, target string) (bool, error) {
	tmp, release := v.b.newTempName("link")
	defer release()
	if err := v.b.fs.Symlink(target, tmp); err != nil {
		return false, errors.Wrapf(err, "failed to create a link for %s", name)
	}
	// rename(2) over an existing link replaces it in one step; over a
	// directory (an object whose name is also another object's directory)
	// it fails, and the view simply lacks that name.
	if err := v.b.fs.Rename(tmp, name); err != nil {
		_ = v.b.fs.Remove(tmp)
		return false, errors.Wrapf(err, "failed to place the link %s", name)
	}
	return true, nil
}

// removeLinkIf removes name if it is a symlink holding target.  Checking
// the target keeps a stale removal from deleting a link that has since been
// pointed somewhere else.
func (v *tierNameView) removeLinkIf(name, target string) (bool, error) {
	existing, err := v.b.fs.Readlink(name)
	if err != nil || existing != target {
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

// unlink withdraws one version of an object: its version link, and the
// bare name if it resolved to that version.
func (v *tierNameView) unlink(n tierLogicalName, key string) error {
	objectPath, err := v.b.objectPath(key)
	if err != nil {
		return err
	}
	if _, err := v.removeLinkIf(v.objectLinkPath(n), objectLinkFrom(n.dir, objectPath)); err != nil {
		return err
	}
	if !v.exact {
		if _, err := v.removeLinkIf(n.currentPath(), n.versionFile()); err != nil {
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
			return 0, v.unlink(name, key)
		}
		return 0, nil
	}
	objectPath, err := v.b.objectPath(key)
	if err != nil {
		return 0, err
	}
	latest, found, err := sm.db.GetLatestETag(sm.db.ObjectHash(meta.SourceURL))
	if err != nil {
		return 0, err
	}
	current := found && latest == meta.ETag
	want := objectLinkFrom(name.dir, objectPath)
	if v.exact {
		return sm.publishExactNameLocked(target, name, want, current)
	}

	if err := v.b.mkdirAll(name.dir); err != nil {
		return 0, err
	}
	changed := 0
	existing, err := v.b.fs.Readlink(name.versionPath())
	switch {
	case err == nil && existing == want:
	case err == nil && sm.judgeVersionLink(target, name.versionPath(), existing) == linkKeep:
		// Another object already holds this name -- two versions whose
		// tags differ only in quoting, say.  The first keeps it; flipping
		// between them every sweep would be worse than either.
		return 0, errors.Errorf("%s already names another object", name.versionPath())
	default:
		if _, err := v.placeLink(name.versionPath(), want); err != nil {
			return changed, err
		}
		changed++
	}
	if current {
		if existing, err := v.b.fs.Readlink(name.currentPath()); err != nil || existing != name.versionFile() {
			if _, err := v.placeLink(name.currentPath(), name.versionFile()); err != nil {
				return changed, err
			}
			changed++
		}
	} else {
		removed, err := v.removeLinkIf(name.currentPath(), name.versionFile())
		if removed {
			changed++
		}
		if err != nil {
			return changed, err
		}
	}
	return changed, nil
}

// publishExactNameLocked is publishTierNameLocked for an exact-names view:
// the object's name leads straight to it while it is the current version,
// and to nothing of its once it is not.
func (sm *StorageManager) publishExactNameLocked(target *tierTarget, name tierLogicalName, want string, current bool) (int, error) {
	v := target.names
	if !current {
		removed, err := v.removeLinkIf(name.currentPath(), want)
		if removed {
			v.pruneDirs(name.dir)
			return 1, err
		}
		return 0, err
	}
	existing, err := v.b.fs.Readlink(name.currentPath())
	switch {
	case err == nil && existing == want:
		return 0, nil
	case err == nil && sm.judgeExactLink(target, name.currentPath(), existing) == linkKeep:
		// Another current object has this name -- the same path in another
		// federation, say.  The first keeps it.
		return 0, errors.Errorf("%s already names another object", name.currentPath())
	}
	if err := v.b.mkdirAll(name.dir); err != nil {
		return 0, err
	}
	if _, err := v.placeLink(name.currentPath(), want); err != nil {
		return 0, err
	}
	return 1, nil
}

// unpublishTierName withdraws an object from its target's names view.
// Callers remove the metadata first and the object last, so the links never
// point at a missing file for longer than it takes to unlink them.
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
	if err := v.unlink(name, target.objectKey(hash)); err != nil {
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

// judgeVersionLink decides whether linkPath, holding dest, is a valid
// version link.
func (sm *StorageManager) judgeVersionLink(target *tierTarget, linkPath, dest string) linkVerdict {
	verdict, _ := sm.judgeVersionLinkMeta(target, linkPath, dest)
	return verdict
}

// judgeVersionLinkMeta is judgeVersionLink, also returning the object's
// metadata when the link is valid.
func (sm *StorageManager) judgeVersionLinkMeta(target *tierTarget, linkPath, dest string) (linkVerdict, *CacheMetadata) {
	prefix := objectLinkFrom(path.Dir(linkPath), posixObjectsDir+"/")
	if !strings.HasPrefix(dest, prefix) {
		return linkRemove, nil
	}
	hash := target.hashFromKey(dest[len(prefix):])
	if hash == "" {
		return linkRemove, nil
	}
	meta, err := sm.db.GetMetadata(hash)
	if err != nil {
		return linkKeep, nil // cannot tell; do not destroy on a read error
	}
	if meta == nil || meta.StorageID != target.id || meta.Completed.IsZero() {
		return linkRemove, nil
	}
	if allowed, known := target.mayHold(meta.SourceURL); known && !allowed {
		return linkRemove, nil
	}
	name, ok := target.names.logicalName(meta.SourceURL, meta.ETag)
	if !ok || target.names.objectLinkPath(name) != linkPath {
		return linkRemove, nil
	}
	return linkKeep, meta
}

// judgeExactLink decides whether linkPath, holding dest, belongs in an
// exact-names view: it must lead to an object on the target that may be
// exposed, whose name is linkPath, and which is the current version.
func (sm *StorageManager) judgeExactLink(target *tierTarget, linkPath, dest string) linkVerdict {
	verdict, meta := sm.judgeVersionLinkMeta(target, linkPath, dest)
	if meta == nil {
		return verdict
	}
	if current, err := sm.isLatest(meta); err != nil {
		return linkKeep
	} else if !current {
		return linkRemove
	}
	return linkKeep
}

// judgeBareLink decides whether the bare name linkPath, holding dest, is
// valid: it must point at one of its own versions in the same directory,
// and that version must be valid and the latest.  readlink resolves the
// version link (the sweep passes what it already read).
func (sm *StorageManager) judgeBareLink(target *tierTarget, linkPath, dest string, readlink func(string) (string, error)) linkVerdict {
	base := path.Base(linkPath)
	if strings.Contains(dest, "/") || !strings.HasPrefix(dest, base+"@") {
		return linkRemove
	}
	versionPath := path.Dir(linkPath) + "/" + dest
	versionDest, err := readlink(versionPath)
	if err != nil {
		return linkRemove
	}
	verdict, meta := sm.judgeVersionLinkMeta(target, versionPath, versionDest)
	if meta == nil {
		return verdict
	}
	if current, err := sm.isLatest(meta); err != nil {
		return linkKeep
	} else if !current {
		return linkRemove
	}
	return linkKeep
}

// isLatest reports whether meta is the version the cache considers current.
func (sm *StorageManager) isLatest(meta *CacheMetadata) (bool, error) {
	latest, found, err := sm.db.GetLatestETag(sm.db.ObjectHash(meta.SourceURL))
	if err != nil {
		return false, err
	}
	return found && latest == meta.ETag, nil
}

// judgeNameLink judges one symlink in the names tree, reading what it needs
// from the filesystem.  It is the check made under the view's lock right
// before a removal, so that nothing changed since the sweep looked is lost.
func (sm *StorageManager) judgeNameLink(target *tierTarget, linkPath string) linkVerdict {
	if !target.names.enabled {
		return linkRemove
	}
	dest, err := target.names.b.fs.Readlink(linkPath)
	if err != nil {
		return linkKeep // gone already, or unreadable: nothing to do here
	}
	if target.names.exact {
		return sm.judgeExactLink(target, linkPath, dest)
	}
	if strings.Contains(path.Base(linkPath), "@") {
		return sm.judgeVersionLink(target, linkPath, dest)
	}
	return sm.judgeBareLink(target, linkPath, dest, target.names.b.fs.Readlink)
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
// It is one pass over the tree plus one over the metadata.  The walk reads
// each link once and judges it against the metadata store -- which costs a
// database lookup, not a filesystem round trip -- fixing a bare name that
// should point elsewhere and removing whatever is stale or foreign; it
// remembers which objects have a valid version link.  The metadata pass then
// publishes only the objects the walk did not see.  In the steady state that
// is one readlink per link and nothing else on the filesystem.  The view's
// lock is taken only around changes, each re-checked under it, so evictions
// are never held up behind the sweep's reads.
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

	seen := hashSet{}
	added, removed, err = cc.walkTierNames(ctx, target, posixNamesDir, seen)
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
func (cc *ConsistencyChecker) walkTierNames(ctx context.Context, target *tierTarget, dir string, seen hashSet) (added, removed int, err error) {
	v := target.names
	sm := cc.storage
	entries, err := v.b.fs.ReadDir(dir)
	if err != nil {
		return 0, 0, errors.Wrapf(err, "failed to list %s on cache tier target %s", dir, target.DisplayURL())
	}

	// removeIf takes the lock and removes name only if it still deserves it.
	removeIf := func(name string, stillStale func() bool) {
		v.mu.Lock()
		defer v.mu.Unlock()
		if stillStale() {
			if err := v.b.fs.Remove(name); err == nil {
				removed++
			}
		}
	}

	dests := map[string]string{} // link name -> what it holds
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return added, removed, err
		}
		name := dir + "/" + e.Name()
		switch {
		case e.IsDir():
			a, r, err := cc.walkTierNames(ctx, target, name, seen)
			added += a
			removed += r
			if err != nil {
				return added, removed, err
			}
			v.mu.Lock()
			_ = v.b.fs.Remove(name) // fails, harmlessly, unless empty
			v.mu.Unlock()
		case e.Type()&fs.ModeSymlink != 0:
			dest, err := v.b.fs.Readlink(name)
			if err != nil {
				if errors.Is(err, errTargetNotResponding) {
					return added, removed, err
				}
				continue
			}
			dests[e.Name()] = dest
		default:
			// The cache only ever puts symlinks and directories here, and
			// the tree is writable only by the cache, so this was put here
			// by someone with the cache's privileges.  It is not the cache's
			// to keep.
			log.Warnf("Removing unexpected file %s from the names view of %s", name, target.DisplayURL())
			removeIf(name, func() bool {
				info, err := v.b.fs.Lstat(name)
				return err == nil && !info.IsDir() && info.Mode()&fs.ModeSymlink == 0
			})
		}
	}

	if v.exact {
		for file, dest := range dests {
			name := dir + "/" + file
			if !v.enabled {
				removeIf(name, func() bool { return sm.judgeNameLink(target, name) == linkRemove })
				continue
			}
			verdict, meta := sm.judgeVersionLinkMeta(target, name, dest)
			if verdict == linkKeep && meta != nil {
				if current, err := sm.isLatest(meta); err == nil && !current {
					verdict = linkRemove
				}
			}
			if verdict == linkRemove {
				removeIf(name, func() bool { return sm.judgeNameLink(target, name) == linkRemove })
				continue
			}
			if meta != nil {
				seen.add(target.hashFromKey(dest[len(objectLinkFrom(dir, posixObjectsDir+"/")):]))
			}
		}
		return added, removed, nil
	}

	readlink := func(name string) (string, error) {
		if path.Dir(name) == dir {
			if dest, ok := dests[path.Base(name)]; ok {
				return dest, nil
			}
		}
		return v.b.fs.Readlink(name)
	}

	// Version links first: they decide which bare names are right.
	type version struct {
		hash InstanceHash
		file string
	}
	currentVersion := map[string]version{} // bare name -> its current, valid version
	for file, dest := range dests {
		if !strings.Contains(file, "@") {
			continue
		}
		name := dir + "/" + file
		if !v.enabled {
			removeIf(name, func() bool { return sm.judgeNameLink(target, name) == linkRemove })
			continue
		}
		verdict, meta := sm.judgeVersionLinkMeta(target, name, dest)
		if verdict == linkRemove {
			removeIf(name, func() bool { return sm.judgeNameLink(target, name) == linkRemove })
			continue
		}
		if meta == nil {
			continue // undecidable now; leave it
		}
		hash := target.hashFromKey(dest[len(objectLinkFrom(dir, posixObjectsDir+"/")):])
		seen.add(hash)
		if current, err := sm.isLatest(meta); err == nil && current {
			currentVersion[file[:strings.IndexByte(file, '@')]] = version{hash: hash, file: file}
		}
	}

	for file, dest := range dests {
		if strings.Contains(file, "@") {
			continue
		}
		name := dir + "/" + file
		if want, ok := currentVersion[file]; ok {
			if dest != want.file {
				// Points at the wrong version; repoint it.
				v.mu.Lock()
				n, err := sm.publishTierNameLocked(target, want.hash)
				v.mu.Unlock()
				added += n
				if err != nil {
					log.Debugf("Could not update %s in the names view of %s: %v", name, target.DisplayURL(), err)
				}
			}
			delete(currentVersion, file)
			continue
		}
		if !v.enabled || sm.judgeBareLink(target, name, dest, readlink) == linkRemove {
			removeIf(name, func() bool { return sm.judgeNameLink(target, name) == linkRemove })
		}
	}
	// A current version whose bare name is missing altogether.
	for _, want := range currentVersion {
		v.mu.Lock()
		n, err := sm.publishTierNameLocked(target, want.hash)
		v.mu.Unlock()
		added += n
		if err != nil {
			log.Debugf("Could not add %s to the names view of %s: %v", want.hash, target.DisplayURL(), err)
		}
	}
	return added, removed, nil
}
