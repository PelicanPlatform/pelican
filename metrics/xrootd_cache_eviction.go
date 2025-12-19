/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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

package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/param"
)

type (
	DirStatistics struct {
		SnapshotStatsResetTime int        `json:"m_sshot_stats_reset_time"`
		UsageUpdateTime        int        `json:"m_usage_update_time"`
		DiskTotal              int64      `json:"m_disk_total"`
		DiskUsed               int64      `json:"m_disk_used"`
		FileUsage              int        `json:"m_file_usage"`
		MetaTotal              int64      `json:"m_meta_total"`
		MetaUsed               int64      `json:"m_meta_used"`
		DirStates              []DirState `json:"m_dir_states"`
	}

	DirState struct {
		DirName        string   `json:"m_dir_name"`
		Stats          DirStats `json:"m_stats"`
		Usage          Usage    `json:"m_usage"`
		Parent         int      `json:"m_parent"`
		DaughtersBegin int      `json:"m_daughters_begin"`
		DaughtersEnd   int      `json:"m_daughters_end"`
	}

	DirStats struct {
		NumIos              int `json:"m_NumIos"`
		Duration            int `json:"m_Duration"`
		BytesHit            int `json:"m_BytesHit"`
		BytesMissed         int `json:"m_BytesMissed"`
		BytesBypassed       int `json:"m_BytesBypassed"`
		BytesWritten        int `json:"m_BytesWritten"`
		StBlocksAdded       int `json:"m_StBlocksAdded"`
		NCksumErrors        int `json:"m_NCksumErrors"`
		StBlocksRemoved     int `json:"m_StBlocksRemoved"`
		NFilesOpened        int `json:"m_NFilesOpened"`
		NFilesClosed        int `json:"m_NFilesClosed"`
		NFilesCreated       int `json:"m_NFilesCreated"`
		NFilesRemoved       int `json:"m_NFilesRemoved"`
		NDirectoriesCreated int `json:"m_NDirectoriesCreated"`
		NDirectoriesRemoved int `json:"m_NDirectoriesRemoved"`
	}

	Usage struct {
		LastOpenTime  int `json:"m_LastOpenTime"`
		LastCloseTime int `json:"m_LastCloseTime"`
		StBlocks      int `json:"m_StBlocks"`
		NFilesOpen    int `json:"m_NFilesOpen"`
		NFiles        int `json:"m_NFiles"`
		NDirectories  int `json:"m_NDirectories"`
	}
)

var (
	XrootdCacheEvictionLastUpdateTime = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xrootd_cache_eviction_last_update_time_seconds",
		Help: "The last time xrootd cache eviction metrics were updated",
	})
	XrootdCacheEvictionDiskUsage = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xrootd_cache_eviction_disk_usage_bytes",
		Help: "The disk usage of the xrootd cache",
	})
	XrootdCacheEvictionSnapshotStatsResetTime = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xrootd_cache_eviction_snapshot_stats_reset_time_seconds",
		Help: "The time when the snapshot statistics were last reset",
	})
	XrootdCacheEvictionDiskTotal = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xrootd_cache_eviction_disk_total_bytes",
		Help: "The total disk space available for the cache",
	})
	XrootdCacheEvictionFileUsage = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xrootd_cache_eviction_file_usage_bytes",
		Help: "The file usage of the xrootd cache",
	})
	XrootdCacheEvictionMetaTotal = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xrootd_cache_eviction_meta_total_bytes",
		Help: "The total metadata storage available for the cache",
	})
	XrootdCacheEvictionMetaUsed = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xrootd_cache_eviction_meta_used_bytes",
		Help: "The used metadata storage for the cache",
	})

	XrootdCacheEvictionDirNumIos = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "xrootd_cache_eviction_dir_num_ios",
		Help: "Number of I/Os per directory",
	}, []string{"dir_name"})
	XrootdCacheEvictionDirDuration = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "xrootd_cache_eviction_dir_duration",
		Help: "Duration of I/Os per directory",
	}, []string{"dir_name"})
	XrootdCacheEvictionDirBytes = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "xrootd_cache_eviction_dir_bytes",
		Help: "Bytes transferred per directory",
	}, []string{"dir_name", "type"})
	XrootdCacheEvictionDirStBlockBytes = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "xrootd_cache_eviction_dir_st_block_bytes",
		Help: "Bytes from storage blocks per directory",
	}, []string{"dir_name", "type"})
	XrootdCacheEvictionDirNCksumErrors = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "xrootd_cache_eviction_dir_n_cksum_errors",
		Help: "Number of checksum errors per directory",
	}, []string{"dir_name"})
	XrootdCacheEvictionDirFiles = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "xrootd_cache_eviction_dir_files_count",
		Help: "File operations per directory (opened, closed, created, removed)",
	}, []string{"dir_name", "type"})
	XrootdCacheEvictionDirDirectories = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "xrootd_cache_eviction_dir_directories_count",
		Help: "Directory operations (created, removed) per directory",
	}, []string{"dir_name", "type"})

	XrootdCacheEvictionDirLastAccessTime = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "xrootd_cache_eviction_dir_last_access_time_seconds",
		Help: "Last access time per directory",
	}, []string{"dir_name", "type"})
	XrootdCacheEvictionDirStBlocksUsage = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "xrootd_cache_eviction_dir_st_blocks_usage_count",
		Help: "Storage blocks usage per directory",
	}, []string{"dir_name"})
	XrootdCacheEvictionDirNFilesOpen = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "xrootd_cache_eviction_dir_n_files_open_count",
		Help: "Number of open files per directory",
	}, []string{"dir_name"})
	XrootdCacheEvictionDirNFiles = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "xrootd_cache_eviction_dir_n_files_count",
		Help: "Number of files per directory",
	}, []string{"dir_name"})
	XrootdCacheEvictionDirNDirectories = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "xrootd_cache_eviction_dir_n_directories_count",
		Help: "Number of directories per directory",
	}, []string{"dir_name"})
)

/*
LaunchXrootdCacheEvictionMonitoring is a function that launches the xrootd cache eviction monitoring.
It reads the stats file from the cache storage location and updates the metrics.
It runs as a goroutine and is responsible for:
  - Reading the stats file
  - Unmarshalling the stats
  - Updating the metrics

The function looks at the file at the path specified by Cache.StorageLocation/namespace/pfc-stats/DirStat.json.
The JSON schema is as follows:

	{
	  "$schema": "http://json-schema.org/draft-07/schema#",
	  "title": "Xrootd Cache Directory Statistics",
	  "description": "Schema for the JSON data from xrootd's cache eviction monitoring (DirStat.json)",
	  "type": "object",
	  "required": [
	    "m_sshot_stats_reset_time",
	    "m_usage_update_time",
	    "m_disk_total",
	    "m_disk_used",
	    "m_file_usage",
	    "m_meta_total",
	    "m_meta_used",
	    "m_dir_states"
	  ],
	  "properties": {
	    "m_sshot_stats_reset_time": {
	      "type": "integer",
	      "description": "The time when the snapshot statistics were last reset (Unix timestamp)."
	    },
	    "m_usage_update_time": {
	      "type": "integer",
	      "description": "The last time the usage statistics were updated (Unix timestamp)."
	    },
	    "m_disk_total": {
	      "type": "integer",
	      "description": "Total disk space available for the cache in bytes."
	    },
	    "m_disk_used": {
	      "type": "integer",
	      "description": "Disk space used by the cache in bytes."
	    },
	    "m_file_usage": {
	      "type": "integer",
	      "description": "The file usage of the xrootd cache."
	    },
	    "m_meta_total": {
	      "type": "integer",
	      "description": "Total metadata storage available for the cache in bytes."
	    },
	    "m_meta_used": {
	      "type": "integer",
	      "description": "Used metadata storage for the cache in bytes."
	    },
	    "m_dir_states": {
	      "type": "array",
	      "description": "An array of statistics for each directory in the cache.",
	      "items": {
	        "$ref": "#/$defs/dirState"
	      }
	    }
	  },
	  "$defs": {
	    "dirState": {
	      "type": "object",
	      "required": [
	        "m_dir_name",
	        "m_stats",
	        "m_usage",
	        "m_parent",
	        "m_daughters_begin",
	        "m_daughters_end"
	      ],
	      "properties": {
	        "m_dir_name": {
	          "type": "string",
	          "description": "The name of the directory."
	        },
	        "m_stats": {
	          "$ref": "#/$defs/dirStats"
	        },
	        "m_usage": {
	          "$ref": "#/$defs/usage"
	        },
	        "m_parent": {
	          "type": "integer",
	          "description": "Index of the parent directory in the m_dir_states array. -1 for the root."
	        },
	        "m_daughters_begin": {
	          "type": "integer",
	          "description": "Start index in m_dir_states for subdirectories. -1 if no subdirectories."
	        },
	        "m_daughters_end": {
	          "type": "integer",
	          "description": "End index in m_dir_states for subdirectories. -1 if no subdirectories."
	        }
	      }
	    },
	    "dirStats": {
	      "type": "object",
	      "description": "Performance and event statistics for a directory.",
	      "required": [
	        "m_NumIos",
	        "m_Duration",
	        "m_BytesHit",
	        "m_BytesMissed",
	        "m_BytesBypassed",
	        "m_BytesWritten",
	        "m_StBlocksAdded",
	        "m_NCksumErrors",
	        "m_StBlocksRemoved",
	        "m_NFilesOpened",
	        "m_NFilesClosed",
	        "m_NFilesCreated",
	        "m_NFilesRemoved",
	        "m_NDirectoriesCreated",
	        "m_NDirectoriesRemoved"
	      ],
	      "properties": {
	        "m_NumIos": { "type": "integer", "description": "Number of I/O operations." },
	        "m_Duration": { "type": "integer", "description": "Duration of I/O operations." },
	        "m_BytesHit": { "type": "integer", "description": "Bytes served from cache." },
	        "m_BytesMissed": { "type": "integer", "description": "Bytes missed in cache." },
	        "m_BytesBypassed": { "type": "integer", "description": "Bytes that bypassed the cache." },
	        "m_BytesWritten": { "type": "integer", "description": "Bytes written to the cache." },
	        "m_StBlocksAdded": { "type": "integer", "description": "Storage blocks added." },
	        "m_NCksumErrors": { "type": "integer", "description": "Number of checksum errors." },
	        "m_StBlocksRemoved": { "type": "integer", "description": "Storage blocks removed." },
	        "m_NFilesOpened": { "type": "integer", "description": "Number of files opened." },
	        "m_NFilesClosed": { "type": "integer", "description": "Number of files closed." },
	        "m_NFilesCreated": { "type": "integer", "description": "Number of files created." },
	        "m_NFilesRemoved": { "type": "integer", "description": "Number of files removed." },
	        "m_NDirectoriesCreated": { "type": "integer", "description": "Number of directories created." },
	        "m_NDirectoriesRemoved": { "type": "integer", "description": "Number of directories removed." }
	      }
	    },
	    "usage": {
	      "type": "object",
	      "description": "Usage statistics for a directory.",
	      "required": [
	        "m_LastOpenTime",
	        "m_LastCloseTime",
	        "m_StBlocks",
	        "m_NFilesOpen",
	        "m_NFiles",
	        "m_NDirectories"
	      ],
	      "properties": {
	        "m_LastOpenTime": { "type": "integer", "description": "Time of the last file open in the directory (Unix timestamp)." },
	        "m_LastCloseTime": { "type": "integer", "description": "Time of the last file close in the directory (Unix timestamp)." },
	        "m_StBlocks": { "type": "integer", "description": "Storage blocks in use." },
	        "m_NFilesOpen": { "type": "integer", "description": "Number of currently open files." },
	        "m_NFiles": { "type": "integer", "description": "Total number of files in the directory." },
	        "m_NDirectories": { "type": "integer", "description": "Total number of subdirectories." }
	      }
	    }
	  }
	}
*/
func LaunchXrootdCacheEvictionMonitoring(ctx context.Context, egrp *errgroup.Group) {
	egrp.Go(func() error {

		statsFile := filepath.Join(param.Cache_StorageLocation.GetString(), "namespace", "pfc-stats", "DirStat.json")

		ticker := time.NewTicker(param.Cache_EvictionMonitoringInterval.GetDuration())
		defer ticker.Stop()

		// We use this to detect if the stats file is stale
		var lastUpdateTime int

		for {
			select {
			case <-ctx.Done():
				log.Trace("Xrootd cache eviction monitoring (context done)")
				return nil
			case <-ticker.C:
				log.Trace("Xrootd cache eviction monitoring (attempting to ingest eviction data)")
				stats, err := os.ReadFile(statsFile)
				if err != nil {
					log.Tracef("Xrootd cache eviction monitoring: failed to read stats file: %v", err)
					if !errors.Is(err, os.ErrNotExist) {
						log.Errorf("Xrootd cache eviction monitoring: failed to read stats file: %v", err)
					}
					continue
				}
				var dirStatistics DirStatistics
				if err := json.Unmarshal(stats, &dirStatistics); err != nil {
					log.Warningf("Xrootd cache eviction monitoring: failed to unmarshal stats: %v", err)
					continue
				}

				log.Tracef("Xrootd cache eviction monitoring (dirStatistics: %s)", stats)

				if dirStatistics.UsageUpdateTime <= lastUpdateTime {
					log.Tracef("Xrootd cache eviction monitoring (stats file has not been updated since last read at %d, but current file timestamp is %d)", lastUpdateTime, dirStatistics.UsageUpdateTime)
					continue
				}

				lastUpdateTime = dirStatistics.UsageUpdateTime
				XrootdCacheEvictionLastUpdateTime.Set(float64(lastUpdateTime))

				XrootdCacheEvictionDiskUsage.Set(float64(dirStatistics.DiskUsed))

				XrootdCacheEvictionSnapshotStatsResetTime.Set(float64(dirStatistics.SnapshotStatsResetTime))
				XrootdCacheEvictionDiskTotal.Set(float64(dirStatistics.DiskTotal))
				XrootdCacheEvictionFileUsage.Set(float64(dirStatistics.FileUsage))
				XrootdCacheEvictionMetaTotal.Set(float64(dirStatistics.MetaTotal))
				XrootdCacheEvictionMetaUsed.Set(float64(dirStatistics.MetaUsed))

				updateXrootdCacheEvictionMetrics(dirStatistics)
			}
		}
	})
}

func updateXrootdCacheEvictionMetrics(dirStatistics DirStatistics) {
	for i, dirState := range dirStatistics.DirStates {
		// Build the full path by traversing up the parent hierarchy
		var pathParts []string
		curr := i
		for curr != -1 {
			pathParts = append(pathParts, dirStatistics.DirStates[curr].DirName)
			curr = dirStatistics.DirStates[curr].Parent
		}

		// Reverse the parts to get the correct order from root to leaf
		for i, j := 0, len(pathParts)-1; i < j; i, j = i+1, j-1 {
			pathParts[i], pathParts[j] = pathParts[j], pathParts[i]
		}

		// Join the path parts. The root directory is an empty string, so we prepend "/"
		dirName := path.Join(pathParts...)
		if dirName == "" {
			dirName = "/"
		} else if dirName[0] != '/' {
			dirName = "/" + dirName
		}
		// DirStats
		XrootdCacheEvictionDirNumIos.WithLabelValues(dirName).Set(float64(dirState.Stats.NumIos))
		XrootdCacheEvictionDirDuration.WithLabelValues(dirName).Set(float64(dirState.Stats.Duration))
		XrootdCacheEvictionDirBytes.WithLabelValues(dirName, "hit").Set(float64(dirState.Stats.BytesHit))
		XrootdCacheEvictionDirBytes.WithLabelValues(dirName, "missed").Set(float64(dirState.Stats.BytesMissed))
		XrootdCacheEvictionDirBytes.WithLabelValues(dirName, "bypassed").Set(float64(dirState.Stats.BytesBypassed))
		XrootdCacheEvictionDirBytes.WithLabelValues(dirName, "written").Set(float64(dirState.Stats.BytesWritten))
		XrootdCacheEvictionDirStBlockBytes.WithLabelValues(dirName, "added").Set(float64(dirState.Stats.StBlocksAdded) * 512)
		XrootdCacheEvictionDirStBlockBytes.WithLabelValues(dirName, "removed").Set(float64(dirState.Stats.StBlocksRemoved) * 512)
		XrootdCacheEvictionDirNCksumErrors.WithLabelValues(dirName).Set(float64(dirState.Stats.NCksumErrors))
		XrootdCacheEvictionDirFiles.WithLabelValues(dirName, "opened").Set(float64(dirState.Stats.NFilesOpened))
		XrootdCacheEvictionDirFiles.WithLabelValues(dirName, "closed").Set(float64(dirState.Stats.NFilesClosed))
		XrootdCacheEvictionDirFiles.WithLabelValues(dirName, "created").Set(float64(dirState.Stats.NFilesCreated))
		XrootdCacheEvictionDirFiles.WithLabelValues(dirName, "removed").Set(float64(dirState.Stats.NFilesRemoved))
		XrootdCacheEvictionDirDirectories.WithLabelValues(dirName, "created").Set(float64(dirState.Stats.NDirectoriesCreated))
		XrootdCacheEvictionDirDirectories.WithLabelValues(dirName, "removed").Set(float64(dirState.Stats.NDirectoriesRemoved))

		// Usage
		XrootdCacheEvictionDirLastAccessTime.WithLabelValues(dirName, "open").Set(float64(dirState.Usage.LastOpenTime))
		XrootdCacheEvictionDirLastAccessTime.WithLabelValues(dirName, "close").Set(float64(dirState.Usage.LastCloseTime))
		XrootdCacheEvictionDirStBlocksUsage.WithLabelValues(dirName).Set(float64(dirState.Usage.StBlocks))
		XrootdCacheEvictionDirNFilesOpen.WithLabelValues(dirName).Set(float64(dirState.Usage.NFilesOpen))
		XrootdCacheEvictionDirNFiles.WithLabelValues(dirName).Set(float64(dirState.Usage.NFiles))
		XrootdCacheEvictionDirNDirectories.WithLabelValues(dirName).Set(float64(dirState.Usage.NDirectories))
	}

}
