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

package origin_serve

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/webdav"

	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_utils"
)

var adiosSelectorRegex = regexp.MustCompile(`^s(\d+)n(\d+)b(\d+)r([01])$`)

type adiosBackend struct {
	fs *adiosFileSystem
}

type AdiosBackendOptions struct {
	ServiceURL    string
	StoragePrefix string
	AuthTokenFile string
}

type adiosRequestSpec struct {
	bpPath    string
	varnames  []string
	step      int
	stepCount int
	blockID   int
	rmOrder   int
}

func newAdiosBackend(opts AdiosBackendOptions) *adiosBackend {
	fs := &adiosFileSystem{
		serviceURL:    strings.TrimSuffix(opts.ServiceURL, "/"),
		storagePrefix: opts.StoragePrefix,
		authTokenFile: opts.AuthTokenFile,
		httpClient:    &http.Client{Transport: config.GetTransport()},
	}
	return &adiosBackend{fs: fs}
}

func (b *adiosBackend) CheckAvailability() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.fs.serviceURL, nil)
	if err != nil {
		return err
	}
	if token := b.fs.readAuthToken(); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := b.fs.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		return fmt.Errorf("adios backend probe failed with status %d", resp.StatusCode)
	}
	return nil
}

func (b *adiosBackend) FileSystem() webdav.FileSystem { return b.fs }
func (b *adiosBackend) Checksummer() server_utils.OriginChecksummer {
	return nil
}

type adiosFileSystem struct {
	serviceURL    string
	storagePrefix string
	authTokenFile string
	httpClient    *http.Client
}

func (fs *adiosFileSystem) Mkdir(context.Context, string, os.FileMode) error {
	return os.ErrPermission
}

func (fs *adiosFileSystem) OpenFile(ctx context.Context, name string, flag int, _ os.FileMode) (webdav.File, error) {
	if flag != os.O_RDONLY {
		return nil, os.ErrPermission
	}

	spec, err := parseAdiosPath(name)
	if err != nil {
		return nil, os.ErrNotExist
	}

	upstreamURL := fs.buildUpstreamURL(spec)
	log.Debugf("ADIOS upstream URL: %s", upstreamURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstreamURL, nil)
	if err != nil {
		return nil, err
	}
	if token := fs.readAuthToken(); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	if ph := server_utils.PelicanHeadersFromContext(ctx); ph != nil {
		if ph.JobId != "" {
			req.Header.Set("X-Pelican-JobId", ph.JobId)
		}
		if ph.Timeout != "" {
			req.Header.Set("X-Pelican-Timeout", ph.Timeout)
		}
	}

	resp, err := fs.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, os.ErrNotExist
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024))
		return nil, fmt.Errorf("adios request failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return &adiosReadFile{
		name:   name,
		reader: bytes.NewReader(payload),
		size:   int64(len(payload)),
		mod:    time.Now(),
	}, nil
}

func (fs *adiosFileSystem) RemoveAll(context.Context, string) error {
	return os.ErrPermission
}

func (fs *adiosFileSystem) Rename(context.Context, string, string) error {
	return os.ErrPermission
}

func (fs *adiosFileSystem) Stat(_ context.Context, name string) (os.FileInfo, error) {
	if _, err := parseAdiosPath(name); err == nil {
		return &adiosFileInfo{name: path.Base(name), size: 0, mod: time.Now()}, nil
	}
	return nil, os.ErrNotExist
}

func (fs *adiosFileSystem) buildUpstreamURL(spec adiosRequestSpec) string {
	bpPath := strings.TrimPrefix(path.Clean("/"+spec.bpPath), "/")
	prefix := strings.TrimPrefix(strings.TrimSuffix(fs.storagePrefix, "/"), "/")

	base := strings.TrimSuffix(fs.serviceURL, "/")
	if prefix != "" {
		base += "/" + prefix
	}
	base += "/" + bpPath

	varnames := append([]string(nil), spec.varnames...)
	if len(varnames) > 1 {
		slices.Sort(varnames)
	}

	if len(varnames) == 1 {
		v := url.Values{}
		v.Set("Varname", varnames[0])
		v.Set("RMOrder", strconv.Itoa(spec.rmOrder))
		v.Set("Block", strconv.Itoa(spec.blockID))
		v.Set("StepStart", strconv.Itoa(spec.step))
		v.Set("StepCount", strconv.Itoa(spec.stepCount))
		return base + "?get&" + v.Encode()
	}

	v := url.Values{}
	v.Set("NVars", strconv.Itoa(len(varnames)))
	v.Set("RMOrder", strconv.Itoa(spec.rmOrder))
	for _, varname := range varnames {
		v.Add("Varname", varname)
		v.Add("StepStart", strconv.Itoa(spec.step))
		v.Add("StepCount", strconv.Itoa(spec.stepCount))
		v.Add("Block", strconv.Itoa(spec.blockID))
	}
	return base + "?batchget&" + v.Encode()
}

func (fs *adiosFileSystem) readAuthToken() string {
	if fs.authTokenFile == "" {
		return ""
	}
	data, err := os.ReadFile(fs.authTokenFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func parseAdiosPath(name string) (adiosRequestSpec, error) {
	cleaned := strings.TrimPrefix(path.Clean("/"+name), "/")
	if cleaned == "" || cleaned == "." {
		return adiosRequestSpec{}, fmt.Errorf("invalid adios path")
	}

	parts := strings.Split(cleaned, "/")
	if len(parts) < 3 {
		return adiosRequestSpec{}, fmt.Errorf("invalid adios path %q", name)
	}

	selector := parts[len(parts)-1]
	matches := adiosSelectorRegex.FindStringSubmatch(selector)
	if matches == nil {
		return adiosRequestSpec{}, fmt.Errorf("invalid selector in %q", name)
	}

	step, _ := strconv.Atoi(matches[1])
	stepCount, _ := strconv.Atoi(matches[2])
	blockID, _ := strconv.Atoi(matches[3])
	rmOrder, _ := strconv.Atoi(matches[4])

	varSegment := parts[len(parts)-2]
	varCandidates := strings.Split(varSegment, "+")
	varnames := make([]string, 0, len(varCandidates))
	for _, rawVar := range varCandidates {
		if rawVar == "" {
			return adiosRequestSpec{}, fmt.Errorf("empty varname in %q", name)
		}
		decoded, err := url.QueryUnescape(rawVar)
		if err != nil {
			return adiosRequestSpec{}, fmt.Errorf("failed to decode varname %q: %w", rawVar, err)
		}
		if !strings.HasPrefix(decoded, "/") {
			decoded = "/" + decoded
		}
		varnames = append(varnames, decoded)
	}

	bpPath := strings.Join(parts[:len(parts)-2], "/")
	if !strings.HasSuffix(bpPath, ".bp") {
		return adiosRequestSpec{}, fmt.Errorf("bp path must end with .bp in %q", name)
	}

	return adiosRequestSpec{
		bpPath:    bpPath,
		varnames:  varnames,
		step:      step,
		stepCount: stepCount,
		blockID:   blockID,
		rmOrder:   rmOrder,
	}, nil
}

type adiosFileInfo struct {
	name  string
	size  int64
	mod   time.Time
	isDir bool
}

func (fi *adiosFileInfo) Name() string      { return fi.name }
func (fi *adiosFileInfo) Size() int64       { return fi.size }
func (fi *adiosFileInfo) Mode() os.FileMode { return 0444 }
func (fi *adiosFileInfo) ModTime() time.Time {
	if fi.mod.IsZero() {
		return time.Now()
	}
	return fi.mod
}
func (fi *adiosFileInfo) IsDir() bool      { return fi.isDir }
func (fi *adiosFileInfo) Sys() interface{} { return nil }

type adiosReadFile struct {
	name   string
	reader *bytes.Reader
	size   int64
	mod    time.Time
}

func (f *adiosReadFile) Read(p []byte) (int, error) {
	return f.reader.Read(p)
}

func (f *adiosReadFile) Seek(offset int64, whence int) (int64, error) {
	return f.reader.Seek(offset, whence)
}

func (f *adiosReadFile) Close() error { return nil }

func (f *adiosReadFile) Write(_ []byte) (int, error) {
	return 0, os.ErrPermission
}

func (f *adiosReadFile) Readdir(_ int) ([]os.FileInfo, error) {
	return nil, fmt.Errorf("readdir not supported on file")
}

func (f *adiosReadFile) Stat() (os.FileInfo, error) {
	return &adiosFileInfo{
		name: path.Base(f.name),
		size: f.size,
		mod:  f.mod,
	}, nil
}
