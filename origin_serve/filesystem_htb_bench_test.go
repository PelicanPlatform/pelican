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
	"fmt"
	"sync"
	"testing"

	"github.com/spf13/afero"

	"github.com/pelicanplatform/pelican/htb"
)

// BenchmarkFileSystemBaseline measures throughput without rate limiting
func BenchmarkFileSystemBaseline(b *testing.B) {
	memFs := afero.NewMemMapFs()
	fs := newAferoFileSystem(memFs, "", nil)

	// Pre-create test file with data
	testData := make([]byte, 4096) // 4KB
	for i := range testData {
		testData[i] = byte(i % 256)
	}
	if err := afero.WriteFile(memFs, "/test.dat", testData, 0644); err != nil {
		b.Fatalf("Failed to write test file: %v", err)
	}

	ctx := context.Background()
	buf := make([]byte, 4096)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		file, err := fs.OpenFile(ctx, "/test.dat", 0, 0)
		if err != nil {
			b.Fatal(err)
		}
		_, err = file.Read(buf)
		if err != nil {
			b.Fatal(err)
		}
		file.Close()
	}

	opsPerSec := float64(b.N) / b.Elapsed().Seconds()
	b.ReportMetric(opsPerSec, "ops/sec")
}

// BenchmarkFileSystemWithRateLimiter measures throughput with rate limiting
func BenchmarkFileSystemWithRateLimiter(b *testing.B) {
	memFs := afero.NewMemMapFs()

	// Create rate limiter with high capacity (shouldn't be bottleneck)
	rateLimiter := htb.New(1000*1000*1000, 1000*1000*1000) // 1 second capacity
	fs := newAferoFileSystemWithRateLimiter(memFs, "", nil, rateLimiter)

	// Pre-create test file
	testData := make([]byte, 4096)
	for i := range testData {
		testData[i] = byte(i % 256)
	}
	if err := afero.WriteFile(memFs, "/test.dat", testData, 0644); err != nil {
		b.Fatalf("Failed to write test file: %v", err)
	}

	ctx := context.WithValue(context.Background(), userInfoKey, &userInfo{User: "bench"})
	buf := make([]byte, 4096)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		file, err := fs.OpenFile(ctx, "/test.dat", 0, 0)
		if err != nil {
			b.Fatal(err)
		}
		_, err = file.Read(buf)
		if err != nil {
			b.Fatal(err)
		}
		file.Close()
	}

	opsPerSec := float64(b.N) / b.Elapsed().Seconds()
	b.ReportMetric(opsPerSec, "ops/sec")
}

// BenchmarkFileSystemWithLimitedRate measures throughput with constrained rate
func BenchmarkFileSystemWithLimitedRate(b *testing.B) {
	memFs := afero.NewMemMapFs()

	// Create rate limiter with limited capacity (100ms)
	rateLimiter := htb.New(100*1000*1000, 100*1000*1000)
	fs := newAferoFileSystemWithRateLimiter(memFs, "", nil, rateLimiter)

	// Pre-create test file
	testData := make([]byte, 4096)
	for i := range testData {
		testData[i] = byte(i % 256)
	}
	if err := afero.WriteFile(memFs, "/test.dat", testData, 0644); err != nil {
		b.Fatalf("Failed to write test file: %v", err)
	}

	ctx := context.WithValue(context.Background(), userInfoKey, &userInfo{User: "bench"})
	buf := make([]byte, 4096)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		file, err := fs.OpenFile(ctx, "/test.dat", 0, 0)
		if err != nil {
			b.Fatal(err)
		}
		_, err = file.Read(buf)
		if err != nil {
			b.Fatal(err)
		}
		file.Close()
	}

	opsPerSec := float64(b.N) / b.Elapsed().Seconds()
	b.ReportMetric(opsPerSec, "ops/sec")
}

// BenchmarkFileSystemConcurrent measures concurrent read throughput
func BenchmarkFileSystemConcurrent(b *testing.B) {
	concurrencyLevels := []int{1, 2, 4, 8, 16}

	for _, concurrency := range concurrencyLevels {
		b.Run(fmt.Sprintf("Baseline-C%d", concurrency), func(b *testing.B) {
			memFs := afero.NewMemMapFs()
			fs := newAferoFileSystem(memFs, "", nil)

			// Pre-create test file
			testData := make([]byte, 4096)
			for i := range testData {
				testData[i] = byte(i % 256)
			}
			if err := afero.WriteFile(memFs, "/test.dat", testData, 0644); err != nil {
				b.Fatalf("Failed to write test file: %v", err)
			}

			ctx := context.Background()

			b.ResetTimer()
			b.ReportAllocs()

			var wg sync.WaitGroup
			opsPerWorker := b.N / concurrency

			for w := 0; w < concurrency; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					buf := make([]byte, 4096)
					for i := 0; i < opsPerWorker; i++ {
						file, err := fs.OpenFile(ctx, "/test.dat", 0, 0)
						if err != nil {
							b.Error(err)
							return
						}
						_, err = file.Read(buf)
						if err != nil {
							b.Error(err)
						}
						file.Close()
					}
				}()
			}

			wg.Wait()

			opsPerSec := float64(b.N) / b.Elapsed().Seconds()
			b.ReportMetric(opsPerSec, "ops/sec")
		})

		b.Run(fmt.Sprintf("RateLimited-C%d", concurrency), func(b *testing.B) {
			memFs := afero.NewMemMapFs()

			// Create rate limiter with 1 second capacity
			rateLimiter := htb.New(1000*1000*1000, 1000*1000*1000)
			fs := newAferoFileSystemWithRateLimiter(memFs, "", nil, rateLimiter)

			// Pre-create test file
			testData := make([]byte, 4096)
			for i := range testData {
				testData[i] = byte(i % 256)
			}
			if err := afero.WriteFile(memFs, "/test.dat", testData, 0644); err != nil {
				b.Fatalf("Failed to write test file: %v", err)
			}

			b.ResetTimer()
			b.ReportAllocs()

			var wg sync.WaitGroup
			opsPerWorker := b.N / concurrency

			for w := 0; w < concurrency; w++ {
				wg.Add(1)
				userID := fmt.Sprintf("user%d", w)
				go func(user string) {
					defer wg.Done()
					ctx := context.WithValue(context.Background(), userInfoKey, &userInfo{User: user})
					buf := make([]byte, 4096)
					for i := 0; i < opsPerWorker; i++ {
						file, err := fs.OpenFile(ctx, "/test.dat", 0, 0)
						if err != nil {
							b.Error(err)
							return
						}
						_, err = file.Read(buf)
						if err != nil {
							b.Error(err)
						}
						file.Close()
					}
				}(userID)
			}

			wg.Wait()

			opsPerSec := float64(b.N) / b.Elapsed().Seconds()
			b.ReportMetric(opsPerSec, "ops/sec")
		})
	}
}

// BenchmarkFileSystemWrite measures write throughput
func BenchmarkFileSystemWrite(b *testing.B) {
	b.Run("Baseline", func(b *testing.B) {
		memFs := afero.NewMemMapFs()
		fs := newAferoFileSystem(memFs, "", nil)

		testData := make([]byte, 4096)
		for i := range testData {
			testData[i] = byte(i % 256)
		}

		ctx := context.Background()

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			filename := fmt.Sprintf("/test%d.dat", i)
			file, err := fs.OpenFile(ctx, filename, 0x242, 0644) // O_CREATE|O_WRONLY|O_TRUNC
			if err != nil {
				b.Fatal(err)
			}
			_, err = file.Write(testData)
			if err != nil {
				b.Fatal(err)
			}
			file.Close()
		}

		opsPerSec := float64(b.N) / b.Elapsed().Seconds()
		b.ReportMetric(opsPerSec, "ops/sec")
	})

	b.Run("RateLimited", func(b *testing.B) {
		memFs := afero.NewMemMapFs()

		rateLimiter := htb.New(1000*1000*1000, 1000*1000*1000)
		fs := newAferoFileSystemWithRateLimiter(memFs, "", nil, rateLimiter)

		testData := make([]byte, 4096)
		for i := range testData {
			testData[i] = byte(i % 256)
		}

		ctx := context.WithValue(context.Background(), userInfoKey, &userInfo{User: "writer"})

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			filename := fmt.Sprintf("/test%d.dat", i)
			file, err := fs.OpenFile(ctx, filename, 0x242, 0644)
			if err != nil {
				b.Fatal(err)
			}
			_, err = file.Write(testData)
			if err != nil {
				b.Fatal(err)
			}
			file.Close()
		}

		opsPerSec := float64(b.N) / b.Elapsed().Seconds()
		b.ReportMetric(opsPerSec, "ops/sec")
	})
}

// BenchmarkRateLimiterOverhead measures pure rate limiter overhead
func BenchmarkRateLimiterOverhead(b *testing.B) {
	b.Run("SingleUser", func(b *testing.B) {
		rateLimiter := htb.New(1000*1000*1000, 1000*1000*1000)
		ctx := context.Background()

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			tokens, err := rateLimiter.Wait(ctx, "user1", 1000) // Request 1 microsecond
			if err != nil {
				b.Fatal(err)
			}
			tokens.Use(500) // Use half
			rateLimiter.Return(tokens)
		}

		opsPerSec := float64(b.N) / b.Elapsed().Seconds()
		b.ReportMetric(opsPerSec, "ops/sec")
	})

	b.Run("MultiUser", func(b *testing.B) {
		rateLimiter := htb.New(1000*1000*1000, 1000*1000*1000)
		ctx := context.Background()

		b.ResetTimer()
		b.ReportAllocs()

		var wg sync.WaitGroup
		numUsers := 10
		opsPerUser := b.N / numUsers

		for u := 0; u < numUsers; u++ {
			wg.Add(1)
			userID := fmt.Sprintf("user%d", u)
			go func(user string) {
				defer wg.Done()
				for i := 0; i < opsPerUser; i++ {
					tokens, err := rateLimiter.Wait(ctx, user, 1000)
					if err != nil {
						b.Error(err)
						return
					}
					tokens.Use(500)
					rateLimiter.Return(tokens)
				}
			}(userID)
		}

		wg.Wait()

		opsPerSec := float64(b.N) / b.Elapsed().Seconds()
		b.ReportMetric(opsPerSec, "ops/sec")
	})
}

// BenchmarkDifferentFileSizes measures throughput with various file sizes
func BenchmarkDifferentFileSizes(b *testing.B) {
	fileSizes := []int{
		1024,        // 1KB
		4096,        // 4KB
		16384,       // 16KB
		65536,       // 64KB
		262144,      // 256KB
		1024 * 1024, // 1MB
	}

	for _, size := range fileSizes {
		b.Run(fmt.Sprintf("Baseline-%dKB", size/1024), func(b *testing.B) {
			memFs := afero.NewMemMapFs()
			fs := newAferoFileSystem(memFs, "", nil)

			testData := make([]byte, size)
			for i := range testData {
				testData[i] = byte(i % 256)
			}
			if err := afero.WriteFile(memFs, "/test.dat", testData, 0644); err != nil {
				b.Fatalf("Failed to write test file: %v", err)
			}

			ctx := context.Background()
			buf := make([]byte, size)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				file, err := fs.OpenFile(ctx, "/test.dat", 0, 0)
				if err != nil {
					b.Fatal(err)
				}
				_, err = file.Read(buf)
				if err != nil {
					b.Fatal(err)
				}
				file.Close()
			}

			bytesPerSec := float64(b.N*size) / b.Elapsed().Seconds()
			b.ReportMetric(bytesPerSec/1024/1024, "MB/s")
		})

		b.Run(fmt.Sprintf("RateLimited-%dKB", size/1024), func(b *testing.B) {
			memFs := afero.NewMemMapFs()

			rateLimiter := htb.New(1000*1000*1000, 1000*1000*1000)
			fs := newAferoFileSystemWithRateLimiter(memFs, "", nil, rateLimiter)

			testData := make([]byte, size)
			for i := range testData {
				testData[i] = byte(i % 256)
			}
			if err := afero.WriteFile(memFs, "/test.dat", testData, 0644); err != nil {
				b.Fatalf("Failed to write test file: %v", err)
			}

			ctx := context.WithValue(context.Background(), userInfoKey, &userInfo{User: "bench"})
			buf := make([]byte, size)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				file, err := fs.OpenFile(ctx, "/test.dat", 0, 0)
				if err != nil {
					b.Fatal(err)
				}
				_, err = file.Read(buf)
				if err != nil {
					b.Fatal(err)
				}
				file.Close()
			}

			bytesPerSec := float64(b.N*size) / b.Elapsed().Seconds()
			b.ReportMetric(bytesPerSec/1024/1024, "MB/s")
		})
	}
}
