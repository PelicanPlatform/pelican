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
	"crypto/rand"
	"fmt"
	"io"

	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/param"
)

// benchEnv holds shared state for benchmarks that need a CacheDB + StorageManager.
// Call newBenchEnv once in each top-level Benchmark function; it uses testing.B.Cleanup
// for teardown.
type benchEnv struct {
	dir     string
	db      *CacheDB
	storage *StorageManager
}

func newBenchEnv(b *testing.B) *benchEnv {
	b.Helper()
	InitIssuerKeyForTests(b)

	dir := b.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	b.Cleanup(cancel)

	db, err := NewCacheDB(ctx, dir)
	require.NoError(b, err)
	b.Cleanup(func() { db.Close() })

	// Enable FD cache so benchmarks reflect production behavior.
	require.NoError(b, param.Set(param.LocalCache_FDCacheSize.GetName(), 1024))
	b.Cleanup(func() { _ = param.Set(param.LocalCache_FDCacheSize.GetName(), 0) })

	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{dir}, 0, egrp)
	require.NoError(b, err)

	return &benchEnv{dir: dir, db: db, storage: storage}
}

// storeInlineObject creates and stores a small inline object, returning its instanceHash.
func storeInlineObject(b *testing.B, env *benchEnv, name string, size int) InstanceHash {
	b.Helper()

	objectHash := env.db.ObjectHash("pelican://bench.example.com/" + name)
	etag := "bench-etag-" + name
	instanceHash := env.db.InstanceHash(etag, objectHash)

	data := make([]byte, size)
	_, _ = rand.Read(data)

	meta := &CacheMetadata{
		ContentLength: int64(size),
		ContentType:   "application/octet-stream",
		SourceURL:     "pelican://bench.example.com/" + name,
		NamespaceID:   1,
		ETag:          etag,
	}

	err := env.storage.StoreInline(context.Background(), instanceHash, meta, data)
	require.NoError(b, err)

	err = env.db.SetLatestETag(objectHash, etag, time.Now())
	require.NoError(b, err)

	return instanceHash
}

// storeDiskObject creates and stores a large disk-backed object, returning its instanceHash.
func storeDiskObject(b *testing.B, env *benchEnv, name string, size int) InstanceHash {
	b.Helper()

	objectHash := env.db.ObjectHash("pelican://bench.example.com/" + name)
	etag := "bench-etag-" + name
	instanceHash := env.db.InstanceHash(etag, objectHash)

	// Init disk storage (creates the file, sets up encryption keys)
	meta, err := env.storage.InitDiskStorage(context.Background(), instanceHash, int64(size), StorageIDFirstDisk)
	require.NoError(b, err)

	// Generate random data and write block-aligned
	data := make([]byte, size)
	_, _ = rand.Read(data)

	err = env.storage.WriteBlocks(instanceHash, 0, data)
	require.NoError(b, err)

	// Set ETag mapping
	err = env.db.SetLatestETag(objectHash, etag, time.Now())
	require.NoError(b, err)

	// Update metadata with ETag
	meta.ETag = etag
	meta.SourceURL = "pelican://bench.example.com/" + name
	err = env.db.SetMetadata(instanceHash, meta)
	require.NoError(b, err)

	return instanceHash
}

// ---------------------------------------------------------------------------
// Benchmark: Metadata lookup (GetLatestETag + GetMetadata round-trip)
// ---------------------------------------------------------------------------

func BenchmarkMetadataLookup(b *testing.B) {
	env := newBenchEnv(b)
	instanceHash := storeInlineObject(b, env, "meta-lookup", 100)

	objectHash := env.db.ObjectHash("pelican://bench.example.com/meta-lookup")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		etag, err := env.db.GetLatestETag(objectHash)
		if err != nil {
			b.Fatal(err)
		}
		ih := env.db.InstanceHash(etag, objectHash)
		if ih != instanceHash {
			b.Fatal("unexpected instanceHash")
		}
		meta, err := env.storage.GetMetadata(ih)
		if err != nil || meta == nil {
			b.Fatal("metadata lookup failed")
		}
	}
}

// ---------------------------------------------------------------------------
// Benchmark: Inline read (small object, < 4 KB)
// ---------------------------------------------------------------------------

func BenchmarkInlineRead(b *testing.B) {
	for _, size := range []int{64, 512, 2048, 4000} {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			env := newBenchEnv(b)
			instanceHash := storeInlineObject(b, env, fmt.Sprintf("inline-%d", size), size)

			buf := make([]byte, size)

			b.SetBytes(int64(size))
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				reader, err := env.storage.NewObjectReader(instanceHash)
				if err != nil {
					b.Fatal(err)
				}
				n, err := io.ReadFull(reader, buf)
				reader.Close()
				if n != size {
					b.Fatalf("short read: %d", n)
				}
				if err != nil && err != io.ErrUnexpectedEOF {
					b.Fatal(err)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Benchmark: Disk read (sequential, full object)
// ---------------------------------------------------------------------------

func BenchmarkDiskReadSequential(b *testing.B) {
	for _, sizeKB := range []int{64, 256, 1024} {
		size := sizeKB * 1024
		b.Run(fmt.Sprintf("size=%dKB", sizeKB), func(b *testing.B) {
			env := newBenchEnv(b)
			instanceHash := storeDiskObject(b, env, fmt.Sprintf("disk-seq-%d", sizeKB), size)

			b.SetBytes(int64(size))
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				reader, err := env.storage.NewObjectReader(instanceHash)
				if err != nil {
					b.Fatal(err)
				}
				n, _ := io.Copy(io.Discard, reader)
				reader.Close()
				if n != int64(size) {
					b.Fatalf("short read: %d", n)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Benchmark: Block encryption and decryption throughput
// ---------------------------------------------------------------------------

func BenchmarkBlockEncryption(b *testing.B) {
	dek := make([]byte, KeySize)
	_, _ = rand.Read(dek)
	nonce := make([]byte, NonceSize)
	_, _ = rand.Read(nonce)

	encryptor, err := NewBlockEncryptor(dek, nonce)
	require.NoError(b, err)

	plaintext := make([]byte, BlockDataSize)
	_, _ = rand.Read(plaintext)

	b.Run("encrypt", func(b *testing.B) {
		b.SetBytes(BlockDataSize)
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, err := encryptor.EncryptBlock(uint32(i), plaintext)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	ciphertext, err := encryptor.EncryptBlock(0, plaintext)
	require.NoError(b, err)

	b.Run("decrypt", func(b *testing.B) {
		b.SetBytes(BlockDataSize)
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, err := encryptor.DecryptBlock(0, ciphertext)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Benchmark: Concurrent reads — throughput scaling by goroutine count
// ---------------------------------------------------------------------------

func BenchmarkConcurrentReads(b *testing.B) {
	const fileSize = 256 * 1024 // 256 KB per object

	for _, goroutines := range []int{1, 4, 16, 64} {
		b.Run(fmt.Sprintf("goroutines=%d", goroutines), func(b *testing.B) {
			env := newBenchEnv(b)
			instanceHash := storeDiskObject(b, env, fmt.Sprintf("conc-%d", goroutines), fileSize)

			b.SetBytes(int64(fileSize) * int64(goroutines))
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				var wg sync.WaitGroup
				wg.Add(goroutines)

				for g := 0; g < goroutines; g++ {
					go func() {
						defer wg.Done()
						reader, err := env.storage.NewObjectReader(instanceHash)
						if err != nil {
							b.Error(err)
							return
						}
						defer reader.Close()
						_, err = io.Copy(io.Discard, reader)
						if err != nil {
							b.Error(err)
						}
					}()
				}

				wg.Wait()
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Benchmark: Random range reads on a large cached file
// ---------------------------------------------------------------------------

func BenchmarkRangeRead(b *testing.B) {
	const fileSize = 1024 * 1024 // 1 MB

	// Use block-aligned sizes: 1, 4, and 16 blocks of plaintext (4080 B each).
	// Aligned reads avoid partial-block overhead in decryptBlocksFromFile.
	for _, rangeBlocks := range []int{1, 4, 16} {
		rangeSize := rangeBlocks * BlockDataSize
		b.Run(fmt.Sprintf("range=%dB", rangeSize), func(b *testing.B) {
			env := newBenchEnv(b)
			instanceHash := storeDiskObject(b, env, fmt.Sprintf("range-%d", rangeSize), fileSize)

			b.SetBytes(int64(rangeSize))
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				// Vary offset each iteration to avoid always reading from the start.
				// Align offset to BlockDataSize so reads start at block boundaries.
				offset := int64(((i * 7919) % (fileSize - rangeSize)) / BlockDataSize * BlockDataSize)
				data, err := env.storage.ReadBlocks(instanceHash, offset, rangeSize)
				if err != nil {
					b.Fatal(err)
				}
				if len(data) != rangeSize {
					b.Fatalf("short read: got %d, want %d", len(data), rangeSize)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Benchmark: ReadBlocksInto (caller-provided buffer, avoids result alloc)
// ---------------------------------------------------------------------------

func BenchmarkRangeReadInto(b *testing.B) {
	const fileSize = 1024 * 1024 // 1 MB

	// Use block-aligned sizes: 1, 4, and 16 blocks of plaintext (4080 B each).
	for _, rangeBlocks := range []int{1, 4, 16} {
		rangeSize := rangeBlocks * BlockDataSize
		b.Run(fmt.Sprintf("range=%dB", rangeSize), func(b *testing.B) {
			env := newBenchEnv(b)
			instanceHash := storeDiskObject(b, env, fmt.Sprintf("range-into-%d", rangeSize), fileSize)

			buf := make([]byte, rangeSize)

			b.SetBytes(int64(rangeSize))
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				// Align offset to block boundaries.
				offset := int64(((i * 7919) % (fileSize - rangeSize)) / BlockDataSize * BlockDataSize)
				n, err := env.storage.ReadBlocksInto(buf, instanceHash, offset)
				if err != nil {
					b.Fatal(err)
				}
				if n != rangeSize {
					b.Fatalf("short read: got %d, want %d", n, rangeSize)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Benchmark: ETag table writes (simulates revalidation LastValidated updates)
// ---------------------------------------------------------------------------

func BenchmarkETagWrite(b *testing.B) {
	env := newBenchEnv(b)

	objectHash := env.db.ObjectHash("pelican://bench.example.com/etag-write")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		err := env.db.SetLatestETag(objectHash, fmt.Sprintf("etag-%d", i), time.Now())
		if err != nil {
			b.Fatal(err)
		}
	}
}

// ---------------------------------------------------------------------------
// Benchmark: Metadata write (simulates revalidation LastValidated updates)
// ---------------------------------------------------------------------------

func BenchmarkMetadataWrite(b *testing.B) {
	env := newBenchEnv(b)

	instanceHash := storeInlineObject(b, env, "meta-write", 100)

	meta, err := env.storage.GetMetadata(instanceHash)
	require.NoError(b, err)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		err := env.db.SetMetadata(instanceHash, meta)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// ---------------------------------------------------------------------------
// Benchmark: ComputeObjectHash + ComputeInstanceHash (pure CPU)
// ---------------------------------------------------------------------------

func BenchmarkHashComputation(b *testing.B) {
	url := "pelican://director.example.com/namespace/deeply/nested/path/to/file.dat"
	etag := "W/\"abc123def456\""
	salt := []byte("benchmark-salt")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		oh := ComputeObjectHash(salt, url)
		_ = ComputeInstanceHash(salt, etag, oh)
	}
}

// ---------------------------------------------------------------------------
// Benchmark: Concurrent inline reads (hot small objects)
// ---------------------------------------------------------------------------

func BenchmarkConcurrentInlineReads(b *testing.B) {
	const objectSize = 512

	for _, goroutines := range []int{1, 4, 16, 64} {
		b.Run(fmt.Sprintf("goroutines=%d", goroutines), func(b *testing.B) {
			env := newBenchEnv(b)
			instanceHash := storeInlineObject(b, env, fmt.Sprintf("inline-conc-%d", goroutines), objectSize)

			b.SetBytes(int64(objectSize) * int64(goroutines))
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				var wg sync.WaitGroup
				wg.Add(goroutines)

				for g := 0; g < goroutines; g++ {
					go func() {
						defer wg.Done()
						reader, err := env.storage.NewObjectReader(instanceHash)
						if err != nil {
							b.Error(err)
							return
						}
						defer reader.Close()
						_, err = io.Copy(io.Discard, reader)
						if err != nil {
							b.Error(err)
						}
					}()
				}

				wg.Wait()
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Benchmark: Disk write (sequential, full object via WriteBlocks)
// ---------------------------------------------------------------------------

func BenchmarkDiskWriteSequential(b *testing.B) {
	for _, sizeKB := range []int{64, 256, 1024} {
		size := sizeKB * 1024
		b.Run(fmt.Sprintf("size=%dKB", sizeKB), func(b *testing.B) {
			env := newBenchEnv(b)

			// Pre-generate random data
			data := make([]byte, size)
			_, _ = rand.Read(data)

			b.SetBytes(int64(size))
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				b.StopTimer()
				name := fmt.Sprintf("disk-write-%d-%d", sizeKB, i)
				objectHash := env.db.ObjectHash("pelican://bench.example.com/" + name)
				etag := "bench-etag-" + name
				instanceHash := env.db.InstanceHash(etag, objectHash)

				_, err := env.storage.InitDiskStorage(context.Background(), instanceHash, int64(size), StorageIDFirstDisk)
				if err != nil {
					b.Fatal(err)
				}
				b.StartTimer()

				err = env.storage.WriteBlocks(instanceHash, 0, data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Benchmark: Disk write+read round-trip (WriteBlocks then ReadBlocks)
// ---------------------------------------------------------------------------

func BenchmarkDiskWriteReadRoundTrip(b *testing.B) {
	for _, sizeKB := range []int{64, 256, 1024} {
		size := sizeKB * 1024
		b.Run(fmt.Sprintf("size=%dKB", sizeKB), func(b *testing.B) {
			env := newBenchEnv(b)

			data := make([]byte, size)
			_, _ = rand.Read(data)

			b.SetBytes(int64(size) * 2) // write + read
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				b.StopTimer()
				name := fmt.Sprintf("disk-rt-%d-%d", sizeKB, i)
				objectHash := env.db.ObjectHash("pelican://bench.example.com/" + name)
				etag := "bench-etag-" + name
				instanceHash := env.db.InstanceHash(etag, objectHash)

				_, err := env.storage.InitDiskStorage(context.Background(), instanceHash, int64(size), StorageIDFirstDisk)
				if err != nil {
					b.Fatal(err)
				}
				b.StartTimer()

				err = env.storage.WriteBlocks(instanceHash, 0, data)
				if err != nil {
					b.Fatal(err)
				}

				result, err := env.storage.ReadBlocks(instanceHash, 0, size)
				if err != nil {
					b.Fatal(err)
				}
				if len(result) != size {
					b.Fatalf("short read: got %d, want %d", len(result), size)
				}
			}
		})
	}
}

// newMultiDirBenchEnv creates a benchEnv with multiple storage directories for
// chunked storage benchmarks.
func newMultiDirBenchEnv(b *testing.B, numDirs int) *benchEnv {
	b.Helper()
	InitIssuerKeyForTests(b)

	dirs := make([]string, numDirs)
	for i := range dirs {
		dirs[i] = b.TempDir()
	}
	dbDir := b.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	b.Cleanup(cancel)

	db, err := NewCacheDB(ctx, dbDir)
	require.NoError(b, err)
	b.Cleanup(func() { db.Close() })

	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, dirs, 0, egrp)
	require.NoError(b, err)

	return &benchEnv{dir: dirs[0], db: db, storage: storage}
}

// storeChunkedDiskObject creates a chunked disk-backed object spread across
// multiple storage directories, writes all data, and returns its instanceHash.
func storeChunkedDiskObject(b *testing.B, env *benchEnv, name string, size int) InstanceHash {
	b.Helper()

	objectHash := env.db.ObjectHash("pelican://bench.example.com/" + name)
	etag := "bench-etag-" + name
	instanceHash := env.db.InstanceHash(etag, objectHash)

	chunkSizeCode := BytesToChunkSizeCode(2 * 1024 * 1024) // 2 MB chunks
	chunkCount := CalculateChunkCount(int64(size), chunkSizeCode)

	// Initialize lazy chunked storage and allocate all chunks
	meta, err := env.storage.InitLazyChunkedStorage(context.Background(), instanceHash, int64(size), chunkSizeCode)
	require.NoError(b, err)

	for i := 0; i < chunkCount; i++ {
		meta, err = env.storage.AllocateChunk(context.Background(), instanceHash, meta, i)
		require.NoError(b, err)
	}

	data := make([]byte, size)
	_, _ = rand.Read(data)

	err = env.storage.WriteBlocks(instanceHash, 0, data)
	require.NoError(b, err)

	meta.ETag = etag
	meta.SourceURL = "pelican://bench.example.com/" + name
	err = env.db.SetMetadata(instanceHash, meta)
	require.NoError(b, err)

	return instanceHash
}

// ---------------------------------------------------------------------------
// Benchmark: Chunked disk read (sequential, full object)
// ---------------------------------------------------------------------------

func BenchmarkChunkedDiskReadSequential(b *testing.B) {
	for _, sizeMB := range []int{4, 8, 16} {
		size := sizeMB * 1024 * 1024
		b.Run(fmt.Sprintf("size=%dMB", sizeMB), func(b *testing.B) {
			env := newMultiDirBenchEnv(b, 3)
			instanceHash := storeChunkedDiskObject(b, env, fmt.Sprintf("chunk-read-%d", sizeMB), size)

			b.SetBytes(int64(size))
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				reader, err := env.storage.NewObjectReader(instanceHash)
				if err != nil {
					b.Fatal(err)
				}
				n, _ := io.Copy(io.Discard, reader)
				reader.Close()
				if n != int64(size) {
					b.Fatalf("short read: %d", n)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Benchmark: Chunked concurrent reads — throughput scaling by goroutine count
// ---------------------------------------------------------------------------

func BenchmarkChunkedConcurrentReads(b *testing.B) {
	const fileSize = 4 * 1024 * 1024 // 4 MB per object

	for _, goroutines := range []int{1, 4, 16, 64} {
		b.Run(fmt.Sprintf("goroutines=%d", goroutines), func(b *testing.B) {
			env := newMultiDirBenchEnv(b, 3)
			instanceHash := storeChunkedDiskObject(b, env, fmt.Sprintf("chunk-conc-%d", goroutines), fileSize)

			b.SetBytes(int64(fileSize) * int64(goroutines))
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				var wg sync.WaitGroup
				wg.Add(goroutines)

				for g := 0; g < goroutines; g++ {
					go func() {
						defer wg.Done()
						reader, err := env.storage.NewObjectReader(instanceHash)
						if err != nil {
							b.Error(err)
							return
						}
						defer reader.Close()
						_, err = io.Copy(io.Discard, reader)
						if err != nil {
							b.Error(err)
						}
					}()
				}

				wg.Wait()
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Benchmark: Chunked disk write (sequential, full object via WriteBlocks)
// ---------------------------------------------------------------------------

func BenchmarkChunkedDiskWriteSequential(b *testing.B) {
	for _, sizeMB := range []int{4, 8, 16} {
		size := sizeMB * 1024 * 1024
		b.Run(fmt.Sprintf("size=%dMB", sizeMB), func(b *testing.B) {
			env := newMultiDirBenchEnv(b, 3)

			data := make([]byte, size)
			_, _ = rand.Read(data)

			chunkSizeCode := BytesToChunkSizeCode(2 * 1024 * 1024)

			b.SetBytes(int64(size))
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				b.StopTimer()
				name := fmt.Sprintf("chunk-write-%d-%d", sizeMB, i)
				objectHash := env.db.ObjectHash("pelican://bench.example.com/" + name)
				etag := "bench-etag-" + name
				instanceHash := env.db.InstanceHash(etag, objectHash)

				chunkCount := CalculateChunkCount(int64(size), chunkSizeCode)

				meta, err := env.storage.InitLazyChunkedStorage(context.Background(), instanceHash, int64(size), chunkSizeCode)
				if err != nil {
					b.Fatal(err)
				}
				for ci := 0; ci < chunkCount; ci++ {
					meta, err = env.storage.AllocateChunk(context.Background(), instanceHash, meta, ci)
					if err != nil {
						b.Fatal(err)
					}
				}
				_ = meta
				b.StartTimer()

				err = env.storage.WriteBlocks(instanceHash, 0, data)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Benchmark: BlockWriter streaming write throughput
// ---------------------------------------------------------------------------

func BenchmarkBlockWriterStreaming(b *testing.B) {
	for _, sizeKB := range []int{64, 256, 1024} {
		size := sizeKB * 1024
		b.Run(fmt.Sprintf("size=%dKB", sizeKB), func(b *testing.B) {
			env := newBenchEnv(b)

			data := make([]byte, size)
			_, _ = rand.Read(data)

			b.SetBytes(int64(size))
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				b.StopTimer()
				name := fmt.Sprintf("bw-stream-%d-%d", sizeKB, i)
				objectHash := env.db.ObjectHash("pelican://bench.example.com/" + name)
				etag := "bench-etag-" + name
				instanceHash := env.db.InstanceHash(etag, objectHash)

				_, err := env.storage.InitDiskStorage(context.Background(), instanceHash, int64(size), StorageIDFirstDisk)
				if err != nil {
					b.Fatal(err)
				}

				bw, err := env.storage.NewBlockWriter(instanceHash, 0, nil, nil)
				if err != nil {
					b.Fatal(err)
				}
				b.StartTimer()

				_, err = bw.Write(data)
				if err != nil {
					b.Fatal(err)
				}
				err = bw.Close()
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Benchmark: Plaintext block cache – cold (first read populates cache) vs hot
// ---------------------------------------------------------------------------

// newBenchEnvWithPtCache creates a benchEnv with the plaintext block cache
// enabled at the given size (in bytes).  Pass 0 to disable.
func newBenchEnvWithPtCache(b *testing.B, ptCacheBytes int) *benchEnv {
	b.Helper()

	require.NoError(b, param.Set(param.LocalCache_MemoryCacheSize.GetName(), ptCacheBytes))
	b.Cleanup(func() { _ = param.Set(param.LocalCache_MemoryCacheSize.GetName(), 0) })

	return newBenchEnv(b)
}

func BenchmarkPlaintextCacheColdRead(b *testing.B) {
	// Cold read: reads a single object repeatedly.  With cache=off
	// every read decrypts from disk; with cache=on the first read
	// populates the cache and subsequent reads are warm (the hot
	// benchmark below is the clean comparison for sustained warm reads).
	const size = 256 * 1024 // 256 KB

	for _, cacheEnabled := range []bool{false, true} {
		label := "off"
		if cacheEnabled {
			label = "on"
		}
		b.Run("cache="+label, func(b *testing.B) {
			cacheSize := 0
			if cacheEnabled {
				cacheSize = 64 * 1024 * 1024 // 64 MB
			}
			env := newBenchEnvWithPtCache(b, cacheSize)
			instanceHash := storeDiskObject(b, env, "pt-cold", size)

			b.SetBytes(int64(size))
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				reader, err := env.storage.NewObjectReader(instanceHash)
				if err != nil {
					b.Fatal(err)
				}
				n, _ := io.Copy(io.Discard, reader)
				reader.Close()
				if n != int64(size) {
					b.Fatalf("short read: %d", n)
				}
			}
		})
	}
}

func BenchmarkPlaintextCacheHotRead(b *testing.B) {
	// Hot read: a single object is read once to warm the cache,
	// then re-read b.N times.  With the cache enabled, subsequent
	// reads skip AES-GCM decryption entirely and just memcpy from
	// the ristretto cache.
	const size = 256 * 1024 // 256 KB

	for _, cacheEnabled := range []bool{false, true} {
		label := "off"
		if cacheEnabled {
			label = "on"
		}
		b.Run("cache="+label, func(b *testing.B) {
			cacheSize := 0
			if cacheEnabled {
				cacheSize = 64 * 1024 * 1024 // 64 MB
			}
			env := newBenchEnvWithPtCache(b, cacheSize)
			instanceHash := storeDiskObject(b, env, "pt-hot", size)

			// Warm: read once to populate ptCache.
			warmReader, err := env.storage.NewObjectReader(instanceHash)
			require.NoError(b, err)
			_, _ = io.Copy(io.Discard, warmReader)
			warmReader.Close()

			// Give ristretto a moment to process the Set buffer.
			time.Sleep(10 * time.Millisecond)

			b.SetBytes(int64(size))
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				reader, err := env.storage.NewObjectReader(instanceHash)
				if err != nil {
					b.Fatal(err)
				}
				n, _ := io.Copy(io.Discard, reader)
				reader.Close()
				if n != int64(size) {
					b.Fatalf("short read: %d", n)
				}
			}
		})
	}
}
