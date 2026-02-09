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
	"context"
	"os"

	"github.com/spf13/afero"
	"golang.org/x/time/rate"

	"github.com/pelicanplatform/pelican/byte_rate"
)

type rateLimitedFs struct {
	afero.Fs
	limiter *rate.Limiter
}

type rateLimitedFile struct {
	afero.File
	limiter *rate.Limiter
}

func newRateLimitedFs(fs afero.Fs, rateLimit byte_rate.ByteRate) afero.Fs {
	if rateLimit <= 0 {
		return fs
	}
	limit := int(rateLimit)
	limiter := rate.NewLimiter(rate.Limit(limit), limit)
	return &rateLimitedFs{Fs: fs, limiter: limiter}
}

func (r *rateLimitedFs) Open(name string) (afero.File, error) {
	file, err := r.Fs.Open(name)
	if err != nil {
		return nil, err
	}
	return &rateLimitedFile{File: file, limiter: r.limiter}, nil
}

func (r *rateLimitedFs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	file, err := r.Fs.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return &rateLimitedFile{File: file, limiter: r.limiter}, nil
}

func (f *rateLimitedFile) Read(p []byte) (int, error) {
	n, err := f.File.Read(p)
	if n > 0 {
		if waitErr := f.waitN(n); waitErr != nil {
			return n, waitErr
		}
	}
	return n, err
}

func (f *rateLimitedFile) Write(p []byte) (int, error) {
	n, err := f.File.Write(p)
	if n > 0 {
		if waitErr := f.waitN(n); waitErr != nil {
			return n, waitErr
		}
	}
	return n, err
}

func (f *rateLimitedFile) ReadAt(p []byte, off int64) (int, error) {
	n, err := f.File.ReadAt(p, off)
	if n > 0 {
		if waitErr := f.waitN(n); waitErr != nil {
			return n, waitErr
		}
	}
	return n, err
}

func (f *rateLimitedFile) WriteAt(p []byte, off int64) (int, error) {
	n, err := f.File.WriteAt(p, off)
	if n > 0 {
		if waitErr := f.waitN(n); waitErr != nil {
			return n, waitErr
		}
	}
	return n, err
}

func (f *rateLimitedFile) waitN(n int) error {
	remaining := n
	for remaining > 0 {
		burst := f.limiter.Burst()
		if burst <= 0 {
			burst = 1
		}
		step := remaining
		if step > burst {
			step = burst
		}
		if err := f.limiter.WaitN(context.Background(), step); err != nil {
			return err
		}
		remaining -= step
	}
	return nil
}
