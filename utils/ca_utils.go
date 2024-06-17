/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

package utils

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

// Write out all the trusted CAs as a CA bundle on disk.  This is useful
// for components that do not use go's trusted CA store
func WriteCABundle(filename string) (int, error) {
	roots, err := loadSystemRoots()
	if err != nil {
		return -1, errors.Wrap(err, "Unable to write CA bundle due to failure when loading system trust roots")
	}

	// Append in any custom CAs we might have
	caFile := param.Server_TLSCACertificateFile.GetString()
	pemContents, err := os.ReadFile(caFile)
	if err == nil {
		roots = append(roots, getCertsFromPEM(pemContents)...)
	}

	if len(roots) == 0 {
		return 0, nil
	}

	dir := filepath.Dir(filename)
	base := filepath.Base(filename)
	file, err := os.CreateTemp(dir, base)
	if err != nil {
		return -1, errors.Wrap(err, "Unable to create CA bundle temporary file")
	}
	defer file.Close()
	if err = os.Chmod(file.Name(), 0644); err != nil {
		return -1, errors.Wrap(err, "Failed to chmod CA bundle temporary file")
	}

	for _, root := range roots {
		if err = pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}); err != nil {
			return -1, errors.Wrap(err, "Failed to write CA into bundle")
		}
	}

	if err := os.Rename(file.Name(), filename); err != nil {
		return -1, errors.Wrapf(err, "Failed to move temporary CA bundle to final location (%v)", filename)
	}

	return len(roots), nil
}

// Periodically write out the system CAs, updating them if the system updates.
// Returns an error if the first attempt at writing fails.  Otherwise, it will
// launch a goroutine and update the entire CA bundle every specified duration.
//
// If we're on a platform (Mac, Windows) that does not provide a CA bundle, we return
// a count of 0 and do not launch the go routine.
func LaunchPeriodicWriteCABundle(ctx context.Context, filename string, sleepTime time.Duration) (count int, err error) {
	count, err = WriteCABundle(filename)
	if err != nil || count == 0 {
		return
	}

	egrp, ok := ctx.Value(config.EgrpKey).(*errgroup.Group)
	if !ok {
		egrp = &errgroup.Group{}
	}
	egrp.Go(func() error {
		ticker := time.NewTicker(sleepTime)
		for {
			select {
			case <-ticker.C:
				_, err := WriteCABundle(filename)
				if err != nil {
					log.Warningln("Failure during periodic CA bundle update:", err)
				}
			case <-ctx.Done():
				return nil
			}
		}
	})

	return
}

// NOTE: Code below is taken from src/crypto/x509/root_unix.go in the go runtime.  Since the
// runtime is BSD-licensed, it is compatible with its inclusion in Pelican
const (
	certFileEnv = "SSL_CERT_FILE"
	certDirEnv  = "SSL_CERT_DIR"
)

var certFiles = []string{
	"/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Gentoo etc.
	"/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora/RHEL 6
	"/etc/ssl/ca-bundle.pem",                            // OpenSUSE
	"/etc/pki/tls/cacert.pem",                           // OpenELEC
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
	"/etc/ssl/cert.pem",                                 // Alpine Linux
}

var certDirectories = []string{
	"/etc/ssl/certs",     // SLES10/SLES11, https://golang.org/issue/12139
	"/etc/pki/tls/certs", // Fedora/RHEL
}

func getCertsFromPEM(pemCerts []byte) []*x509.Certificate {
	result := make([]*x509.Certificate, 0)
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}
		certBytes := block.Bytes
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			continue
		}
		result = append(result, cert)
	}
	return result
}

func loadSystemRoots() ([]*x509.Certificate, error) {
	// The code below only works on Linux; other platforms require syscalls
	// On those, we simply return no system CAs.
	roots := make([]*x509.Certificate, 0)
	if os := runtime.GOOS; os != "linux" {
		return roots, nil
	}

	files := certFiles
	if f := os.Getenv(certFileEnv); f != "" {
		files = []string{f}
	}

	var firstErr error
	for _, file := range files {
		pemCerts, err := os.ReadFile(file)
		if err == nil {
			roots = append(roots, getCertsFromPEM(pemCerts)...)
			break
		}
		if firstErr == nil && !os.IsNotExist(err) {
			firstErr = err
		}
	}

	dirs := certDirectories
	if d := os.Getenv(certDirEnv); d != "" {
		// OpenSSL and BoringSSL both use ":" as the SSL_CERT_DIR separator.
		// See:
		//  * https://golang.org/issue/35325
		//  * https://www.openssl.org/docs/man1.0.2/man1/c_rehash.html
		dirs = strings.Split(d, ":")
	}

	for _, directory := range dirs {
		fis, err := readUniqueDirectoryEntries(directory)
		if err != nil {
			if firstErr == nil && !os.IsNotExist(err) {
				firstErr = err
			}
			continue
		}
		for _, fi := range fis {
			data, err := os.ReadFile(directory + "/" + fi.Name())
			if err == nil {
				roots = append(roots, getCertsFromPEM(data)...)
			}
		}
	}

	if len(roots) > 0 || firstErr == nil {
		return roots, nil
	}

	return nil, firstErr
}

// readUniqueDirectoryEntries is like os.ReadDir but omits
// symlinks that point within the directory.
func readUniqueDirectoryEntries(dir string) ([]fs.DirEntry, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	uniq := files[:0]
	for _, f := range files {
		if !isSameDirSymlink(f, dir) {
			uniq = append(uniq, f)
		}
	}
	return uniq, nil
}

// isSameDirSymlink reports whether a file in a dir is a symlink with a
// target not containing a slash.
func isSameDirSymlink(f fs.DirEntry, dir string) bool {
	if f.Type()&fs.ModeSymlink == 0 {
		return false
	}
	target, err := os.Readlink(filepath.Join(dir, f.Name()))
	return err == nil && !strings.Contains(target, "/")
}
