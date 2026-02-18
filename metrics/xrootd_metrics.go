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

package metrics

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"math"
	"net"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/utils"
)

type (
	SummaryStatType string
	UserId          struct {
		Id uint32
	}

	// userid as in XRootD message info field
	XrdUserId struct {
		Prot string
		User string
		Pid  int
		Sid  int
		Host string
	}

	UserRecord struct {
		AuthenticationProtocol string
		User                   string
		DN                     string
		Role                   string
		Org                    string
		Groups                 []string
		Project                string
		XrdUserId              XrdUserId // Back reference to the XRootD user ID generating this record
	}

	FileId struct {
		Id uint32
	}

	FileRecord struct {
		UserId     UserId
		Path       string
		ReadOps    uint32
		ReadvOps   uint32
		WriteOps   uint32
		ReadvSegs  uint64
		ReadBytes  uint64
		ReadvBytes uint64
		WriteBytes uint64
	}

	PathList struct {
		Paths []string
	}

	XrdXrootdMonHeader struct {
		Code byte   // = | d | f | g | i | p | r | t | u | x
		Pseq byte   // packet sequence
		Plen uint16 // packet length
		Stod int32  // Unix time at Server start
	}

	XrdXrootdMonMap struct {
		Hdr    XrdXrootdMonHeader
		Dictid uint32
		Info   []byte
	}

	recTval byte

	XrdXrootdMonFileHdr struct {
		RecType recTval
		RecFlag byte
		RecSize int16
		FileId  uint32
		UserId  uint32
		NRecs0  int16
		NRecs1  int16
	}

	XrdXrootdMonFileTOD struct {
		Hdr  XrdXrootdMonFileHdr
		TBeg int32
		TEnd int32
		SID  int64
	}

	XrdXrootdMonFileLFN struct {
		User uint32
		Lfn  [1032]byte
	}

	XrdXrootdMonFileOPN struct {
		Hdr XrdXrootdMonFileHdr
		Fsz int64
		Ufn XrdXrootdMonFileLFN
	}

	XrdXrootdMonStatXFR struct {
		Read  int64 // Bytes read from file using read()
		Readv int64 // Bytes read from file using readv()
		Write int64 // Bytes written to file
	}

	XrdXrootdMonFileXFR struct {
		Hdr XrdXrootdMonFileHdr // Header with recType == isXfr
		Xfr XrdXrootdMonStatXFR
	}

	XrdXrootdMonStatOPS struct { // 48B
		Read  int32 // Number of read() calls
		Readv int32 // Number of readv() calls
		Write int32 // Number of write() calls
		RsMin int16 // Smallest readv() segment count
		RsMax int16 // Largest readv() segment count
		Rsegs int64 // Number of readv() segments
		RdMin int32 // Smallest read() request size
		RdMax int32 // Largest read() request size
		RvMin int32 // Smallest readv() request size
		RvMax int32 // Largest readv() request size
		WrMin int32 // Smallest write() request size
		WrMax int32 // Largest write() request size
	}

	// XrdXrootdMonFileCLS represents a variable length structure and
	// includes other structures that are "Always present" or "OPTIONAL".
	// The OPTIONAL parts are not included here as they require more context.
	XrdXrootdMonFileCLS struct {
		Hdr XrdXrootdMonFileHdr // Always present
		Xfr XrdXrootdMonStatXFR // Always present
		Ops XrdXrootdMonStatOPS // OPTIONAL
		// Ssq XrdXrootdMonStatSSQ // OPTIONAL, not implemented here yet
	}

	XrdXrootdMonGS struct {
		Hdr  XrdXrootdMonHeader
		TBeg int   // UNIX time of first entry
		TEnd int   // UNIX time of last entry
		SID  int64 // Provider identification
	}

	// Cache g-stream: https://xrootd.slac.stanford.edu/doc/dev56/xrd_monitoring.htm#_Toc138968526
	CacheGS struct {
		AccessCnt    uint32 `json:"access_cnt"`
		AttachT      int64  `json:"attach_t"`
		ByteBypass   int64  `json:"b_bypass"`
		ByteHit      int64  `json:"b_hit"`
		ByteMiss     int64  `json:"b_miss"`
		BlkSize      int    `json:"blk_size"`
		DetachT      int64  `json:"detach_t"`
		Event        string `json:"event"`
		Lfn          string `json:"lfn"`
		NBlocks      int    `json:"n_blks"`
		NBlocksDone  int    `json:"n_blks_done"`
		NCksErrs     int    `json:"n_cks_errs"`
		Size         int64  `json:"size"`
		ByteToDisk   int64  `json:"b_todisk"`
		BytePrefetch int64  `json:"b_prefetch"`
	}

	// Throttle plug-in g-stream
	ThrottleGS struct {
		IOWaitTime float64 `json:"io_wait"`
		IOActive   int     `json:"io_active"`
		IOTotal    int     `json:"io_total"`
	}

	OssGStreamEvent struct {
		Event string `json:"event"`
	}
	OssS3CacheGs struct {
		Event     string  `json:"event"`
		HitB      int     `json:"hit_b"`      // Bytes that were served to the client directly from the cache (a "cache hit")
		MissB     int     `json:"miss_b"`     // Bytes that were served to the client that were a cache miss (not immediately available).
		FullHit   int     `json:"full_hit"`   // Count of read requests from the client that were completely served from the cache.
		PartHit   int     `json:"part_hit"`   // Count of read requests from the client that were partially served from the cache.
		Miss      int     `json:"miss"`       // Count of read requests that were entirely a miss.
		BypassB   int     `json:"bypass_b"`   // Bytes that were read in "bypass mode", skipping the cache. Typically, this is from read requests that are larger than the cache size.
		Bypass    int     `json:"bypass"`     // Count of read requests that were served by bypassing the cache.
		FetchB    int     `json:"fetch_b"`    // Bytes fetched from S3 triggered by cache misses. Note the cache may read in more bytes than requested for the miss.
		Fetch     int     `json:"fetch"`      // Count of GET requests sent to S3.
		UnusedB   int     `json:"unused_b"`   // Count of bytes that were fetched from S3 but not sent to the client.
		PrefetchB int     `json:"prefetch_b"` // Bytes prefetched from S3 independent of a client request.
		Prefetch  int     `json:"prefetch"`   // Count of prefetch requests sent to S3.
		Errors    int     `json:"errors"`     // Count of errors encountered.
		BypassS   float64 `json:"bypass_s"`   // Seconds spent in GET requests serving bypass requests.
		FetchS    float64 `json:"fetch_s"`    // Seconds spent in GET requests serving cache misses.
	}
	OSSStatsGs struct {
		Event           string  `json:"event"`
		Reads           int     `json:"reads"`
		Writes          int     `json:"writes"`
		Stats           int     `json:"stats"`
		Pgreads         int     `json:"pgreads"`
		Pgwrites        int     `json:"pgwrites"`
		Readvs          int     `json:"readvs"`
		ReadvSegs       int     `json:"readv_segs"`
		Dirlists        int     `json:"dirlists"`
		DirlistEnts     int     `json:"dirlist_ents"`
		Truncates       int     `json:"truncates"`
		Unlinks         int     `json:"unlinks"`
		Chmods          int     `json:"chmods"`
		Opens           int     `json:"opens"`
		Renames         int     `json:"renames"`
		SlowReads       int     `json:"slow_reads"`
		SlowWrites      int     `json:"slow_writes"`
		SlowStats       int     `json:"slow_stats"`
		SlowPgreads     int     `json:"slow_pgreads"`
		SlowPgwrites    int     `json:"slow_pgwrites"`
		SlowReadvs      int     `json:"slow_readvs"`
		SlowReadvSegs   int     `json:"slow_readv_segs"`
		SlowDirlists    int     `json:"slow_dirlists"`
		SlowDirlistEnts int     `json:"slow_dirlist_ents"`
		SlowTruncates   int     `json:"slow_truncates"`
		SlowUnlinks     int     `json:"slow_unlinks"`
		SlowChmods      int     `json:"slow_chmods"`
		SlowOpens       int     `json:"slow_opens"`
		SlowRenames     int     `json:"slow_renames"`
		OpenT           float64 `json:"open_t"`
		ReadT           float64 `json:"read_t"`
		ReadvT          float64 `json:"readv_t"`
		PgreadT         float64 `json:"pgread_t"`
		WriteT          float64 `json:"write_t"`
		PgwriteT        float64 `json:"pgwrite_t"`
		DirlistT        float64 `json:"dirlist_t"`
		StatT           float64 `json:"stat_t"`
		TruncateT       float64 `json:"truncate_t"`
		UnlinkT         float64 `json:"unlink_t"`
		RenameT         float64 `json:"rename_t"`
		ChmodT          float64 `json:"chmod_t"`
		SlowOpenT       float64 `json:"slow_open_t"`
		SlowReadT       float64 `json:"slow_read_t"`
		SlowReadvT      float64 `json:"slow_readv_t"`
		SlowPgreadT     float64 `json:"slow_pgread_t"`
		SlowWriteT      float64 `json:"slow_write_t"`
		SlowPgwriteT    float64 `json:"slow_pgwrite_t"`
		SlowDirlistT    float64 `json:"slow_dirlist_t"`
		SlowStatT       float64 `json:"slow_stat_t"`
		SlowTruncateT   float64 `json:"slow_truncate_t"`
		SlowUnlinkT     float64 `json:"slow_unlink_t"`
		SlowRenameT     float64 `json:"slow_rename_t"`
		SlowChmodT      float64 `json:"slow_chmod_t"`
	}

	// Common dflthdr structure
	DfltHdr struct {
		Code string `json:"code"`
		Pseq int    `json:"pseq"`
		Stod int    `json:"stod"`
		Sid  int    `json:"sid"`
		Gs   GSInfo `json:"gs"`
	}

	GSInfo struct {
		Type string `json:"type"`
		Tbeg int    `json:"tbeg"`
		Tend int    `json:"tend"`
	}

	CacheAccessStat struct {
		Hit      int64
		Miss     int64
		Bypass   int64
		Prefetch int64
		ToDisk   int64
	}

	SummaryPathStat struct {
		Id    string `xml:"id,attr"`
		Lp    string `xml:"lp"`   // The minimally reduced logical file system path i.e. top-level namespace
		Free  int    `xml:"free"` // Kilobytes available
		Total int    `xml:"tot"`  // Kilobytes allocated
	}

	SummaryPath struct {
		Idx   int               `xml:",chardata"`
		Stats []SummaryPathStat `xml:"stats"`
	}

	SummaryCacheStore struct {
		Size int `xml:"size"`
		Used int `xml:"used"`
		Min  int `xml:"min"`
		Max  int `xml:"max"`
	}

	SummaryCacheMemory struct {
		Size int `xml:"size"`
		Used int `xml:"used"`
		Wq   int `xml:"wq"`
	}

	ProcTimes struct {
		Seconds      int `xml:"s"`
		MicroSeconds int `xml:"u"`
	}

	SummaryStat struct {
		Id                 SummaryStatType    `xml:"id,attr"`
		Total              int                `xml:"tot"`
		In                 int                `xml:"in"`
		Out                int                `xml:"out"`
		Threads            int                `xml:"threads"`
		Idle               int                `xml:"idle"`
		Queued             int                `xml:"inq"`
		Jobs               int                `xml:"jobs"`
		LongestQueue       int                `xml:"maxinq"`
		ThreadCreations    int                `xml:"tcr"`
		ThreadDestructions int                `xml:"tde"`
		ThreadLimitReached int                `xml:"tlimr"`
		Paths              SummaryPath        `xml:"paths"` // For Oss Summary Data
		Store              SummaryCacheStore  `xml:"store"`
		Memory             SummaryCacheMemory `xml:"mem"`
		ProcSystem         ProcTimes          `xml:"sys"`
		ProcUser           ProcTimes          `xml:"usr"`
	}

	SummaryStatistics struct {
		Version string        `xml:"ver,attr"`
		Program string        `xml:"pgm,attr"`
		Stats   []SummaryStat `xml:"stats"`
	}

	processUtilizationState struct {
		sync.Mutex
		lastUserSeconds float64
		lastSysSeconds  float64
		lastUpdateTime  time.Time
	}

	XrdCurlPrefetchStats struct {
		Count     float64 `json:"count"`
		Expired   float64 `json:"expired"`
		Failed    float64 `json:"failed"`
		ReadsHit  float64 `json:"reads_hit"`
		ReadsMiss float64 `json:"reads_miss"`
		BytesUsed float64 `json:"bytes_used"`
	}

	XrdCurlFileStats struct {
		Prefetch XrdCurlPrefetchStats `json:"prefetch"`
	}

	XrdCurlQueueStats struct {
		Produced float64 `json:"produced"`
		Consumed float64 `json:"consumed"`
		Pending  float64 `json:"pending"`
		Rejected float64 `json:"rejected"`
	}

	XrdCurlStats struct {
		Event   string            `json:"event"`
		Start   float64           `json:"start"`
		Now     float64           `json:"now"`
		File    XrdCurlFileStats  `json:"file"`
		Workers json.RawMessage   `json:"workers"`
		Queues  XrdCurlQueueStats `json:"queues"`
	}
)

// String returns a human-readable representation of XrdCurlStats
func (s XrdCurlStats) String() string {
	startTime := time.Unix(int64(s.Start), int64((s.Start-float64(int64(s.Start)))*1e9))
	nowTime := time.Unix(int64(s.Now), int64((s.Now-float64(int64(s.Now)))*1e9))
	return fmt.Sprintf("XrdCurlStats{Event=%s, Start=%s, Now=%s, File.Prefetch={Count=%.0f, Expired=%.0f, Failed=%.0f, ReadsHit=%.0f, ReadsMiss=%.0f, BytesUsed=%.0f}, Queues={Produced=%.0f, Consumed=%.0f, Pending=%.0f, Rejected=%.0f}, Workers=%s}",
		s.Event,
		startTime.Format(time.RFC3339),
		nowTime.Format(time.RFC3339),
		s.File.Prefetch.Count,
		s.File.Prefetch.Expired,
		s.File.Prefetch.Failed,
		s.File.Prefetch.ReadsHit,
		s.File.Prefetch.ReadsMiss,
		s.File.Prefetch.BytesUsed,
		s.Queues.Produced,
		s.Queues.Consumed,
		s.Queues.Pending,
		s.Queues.Rejected,
		string(s.Workers))
}

// XrdXrootdMonFileHdr
// Ref: https://github.com/xrootd/xrootd/blob/f3b2e86b9b80bb35f97dd4ad30c4cd5904902a4c/src/XrdXrootd/XrdXrootdMonData.hh#L173
const (
	isClose recTval = iota
	isOpen
	isTime
	isXfr
	isDisc
)

const (
	XROOTD_MON_PIDSHFT = int64(56)
	XROOTD_MON_PIDMASK = int64(0xff)
)

// Summary data types
const (
	LinkStat  SummaryStatType = "link"  // https://xrootd.slac.stanford.edu/doc/dev55/xrd_monitoring.htm#_Toc99653739
	SchedStat SummaryStatType = "sched" // https://xrootd.slac.stanford.edu/doc/dev55/xrd_monitoring.htm#_Toc99653745
	OssStat   SummaryStatType = "oss"   // https://xrootd.slac.stanford.edu/doc/dev55/xrd_monitoring.htm#_Toc99653741
	CacheStat SummaryStatType = "cache" // https://xrootd.slac.stanford.edu/doc/dev55/xrd_monitoring.htm#_Toc99653733
	ProcStat  SummaryStatType = "proc"  // https://xrootd.web.cern.ch/doc/dev57/xrd_monitoring.htm#_Toc138968507
)

// These are the names of the events that are sent by XRootD over the g-stream from the OSS layer
const (
	OssStatsEvent    = "oss_stats"
	S3FileStatsEvent = "s3file_stats"
)

var (
	// TODO: Remove this metric (the line directly below)
	// The renamed metric was added in v7.16
	PacketsReceived = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_monitoring_packets_received",
		Help: "The total number of monitoring UDP packets received",
	})

	PacketsReceivedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_monitoring_packets_received_total",
		Help: "The total number of monitoring UDP packets received",
	})

	// TODO: Remove this metric (the line directly below)
	// The renamed metric was added in v7.16
	TransferReadvSegs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "xrootd_transfer_readv_segments_count",
		Help: "Number of segments in readv operations",
	}, []string{"path", "ap", "dn", "role", "org", "proj", "network"})

	TransferReadvSegsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "xrootd_transfer_readv_segments_total",
		Help: "Number of segments in readv operations",
	}, []string{"path", "ap", "dn", "role", "org", "proj", "network"})

	// TODO: Remove this metric (the line directly below)
	// The renamed metric was added in v7.16
	TransferOps = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "xrootd_transfer_operations_count",
		Help: "Number of transfer operations performed",
	}, []string{"path", "ap", "dn", "role", "org", "proj", "type", "network"})

	TransferOpsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "xrootd_transfer_operations_total",
		Help: "Number of transfer operations performed",
	}, []string{"path", "ap", "dn", "role", "org", "proj", "type", "network"})

	TransferBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "xrootd_transfer_bytes",
		Help: "Bytes of transfers",
	}, []string{"path", "ap", "dn", "role", "org", "proj", "type", "network"})

	Threads = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "xrootd_sched_thread_count",
		Help: "Number of scheduler threads",
	}, []string{"state"})

	ThreadCreations = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_sched_thread_creations",
		Help: "Number of scheduler thread creations",
	})

	ThreadDestructions = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_sched_thread_destructions",
		Help: "Number of scheduler thread destructions",
	})

	ThreadLimitReached = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_sched_thread_limit_reached",
		Help: "Number of times the scheduler thread limit has been reached",
	})

	Jobs = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xrootd_sched_jobs",
		Help: "Number of scheduler jobs requiring a thread",
	})

	LongestQueue = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xrootd_sched_queue_longest_length",
		Help: "Length of the longest run-queue",
	})

	Queued = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xrootd_sched_queued",
		Help: "Number of jobs queued",
	})

	// TODO: Remove this metric (the line directly below)
	// The renamed metric was added in v7.16
	Connections = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_server_connection_count",
		Help: "Aggregate number of server connections",
	})

	ConnectionsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_server_connections_total",
		Help: "Aggregate number of server connections",
	})

	BytesXfer = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "xrootd_server_bytes",
		Help: "Number of bytes read into the server",
	}, []string{"direction"})

	// TODO: Remove this metric (the line directly below)
	// The renamed metric was added in v7.16
	BytesXferTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "xrootd_server_bytes_total",
		Help: "Number of bytes read into the server",
	}, []string{"direction"})

	StorageVolume = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "xrootd_storage_volume_bytes",
		Help: "Storage volume usage on the server",
	}, []string{"ns", "type", "server_type"}) // type: total/free; server_type: origin/cache

	CacheAccess = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "xrootd_cache_access_bytes",
		Help: "Number of bytes the data requested is in the cache or not",
	}, []string{"path", "type"}) // type: hit/miss/bypass

	ServerTotalIO = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_server_io_total",
		Help: "Total storage operations in origin/cache server",
	})

	ServerActiveIO = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xrootd_server_io_active",
		Help: "Number of ongoing storage operations in origin/cache server",
	})

	// TODO: Remove this metric (the line directly below)
	// The renamed metric was added in v7.16
	ServerIOWaitTime = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_server_io_wait_time",
		Help: "The aggregate time spent in storage operations in origin/cache server",
	})

	ServerIOWaitTimeTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_server_io_wait_seconds_total",
		Help: "The aggregate time spent in storage operations in origin/cache server",
	})

	OssReadsCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_oss_reads_total",
		Help: "The total number of read operations on the OSS",
	})

	OssWritesCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_oss_writes_total",
		Help: "The total number of write operations on the OSS",
	})

	OssStatsCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_oss_stats_total",
		Help: "The total number of stat operations on the OSS",
	})

	OssPgReadsCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_oss_pgreads_total",
		Help: "The total number of page read operations on the OSS",
	})

	OssPgWritesCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_oss_pgwrites_total",
		Help: "The total number of page write operations on the OSS",
	})

	OssReadvCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_oss_readv_total",
		Help: "The total number of readv operations on the OSS",
	})

	OssReadvSegsCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_oss_readv_segments_total",
		Help: "The total number of segments in readv operations on the OSS",
	})

	OssDirlistCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_oss_dirlists_total",
		Help: "The total number of directory list operations on the OSS",
	})

	OssDirlistEntsCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_oss_dirlist_entries_total",
		Help: "The total number of directory list entries on the OSS",
	})

	OssTruncateCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_oss_truncates_total",
		Help: "The total number of truncate operations on the OSS",
	})

	OssUnlinkCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_oss_unlinks_total",
		Help: "The total number of unlink operations on the OSS",
	})

	OssChmodCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_oss_chmods_total",
		Help: "The total number of chmod operations on the OSS",
	})

	OssOpensCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_oss_opens_total",
		Help: "The total number of open operations on the OSS",
	})

	OssRenamesCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_oss_renames_total",
		Help: "The total number of rename operations on the OSS",
	})

	OssSlowReadsCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_oss_slow_reads_total",
		Help: "The total number of slow read operations on the OSS",
	})

	OssSlowWritesCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_oss_slow_writes_total",
		Help: "The total number of slow write operations on the OSS",
	})

	OssSlowStatsCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_oss_slow_stats_total",
		Help: "The total number of slow stat operations on the OSS",
	})

	OssSlowPgReadsCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_oss_slow_pgreads_total",
		Help: "The total number of slow page read operations on the OSS",
	})

	OssSlowPgWritesCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_oss_slow_pgwrites_total",
		Help: "The total number of slow page write operations on the OSS",
	})

	OssSlowReadvCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_oss_slow_readv_total",
		Help: "The total number of slow readv operations on the OSS",
	})

	OssSlowReadvSegsCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_oss_slow_readv_segments_total",
		Help: "The total number of segments in slow readv operations on the OSS",
	})

	OssSlowDirlistCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_oss_slow_dirlists_total",
		Help: "The total number of slow directory list operations on the OSS",
	})

	OssSlowDirlistEntsCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_oss_slow_dirlist_entries_total",
		Help: "The total number of slow directory list entries on the OSS",
	})

	OssSlowTruncateCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_oss_slow_truncates_total",
		Help: "The total number of slow truncate operations on the OSS",
	})

	OssSlowUnlinkCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_oss_slow_unlinks_total",
		Help: "The total number of slow unlink operations on the OSS",
	})

	OssSlowChmodCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_oss_slow_chmods_total",
		Help: "The total number of slow chmod operations on the OSS",
	})

	OssSlowOpensCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_oss_slow_opens_total",
		Help: "The total number of slow open operations on the OSS",
	})

	OssSlowRenamesCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_oss_slow_renames_total",
		Help: "The total number of slow rename operations on the OSS",
	})

	TimeHistogramBuckets = prometheus.LinearBuckets(0.0001, 0.0001, 10)

	OssOpenTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "xrootd_oss_open_time_seconds",
		Help:    "The time taken for open operations on the OSS",
		Buckets: TimeHistogramBuckets,
	})

	OssReadTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "xrootd_oss_read_time_seconds",
		Help:    "The time taken for read operations on the OSS",
		Buckets: TimeHistogramBuckets,
	})

	OssReadvTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "xrootd_oss_readv_time_seconds",
		Help:    "The time taken for readv operations on the OSS",
		Buckets: TimeHistogramBuckets,
	})

	OssPgReadTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "xrootd_oss_pgread_time_seconds",
		Help:    "The time taken for page read operations on the OSS",
		Buckets: TimeHistogramBuckets,
	})

	OssWriteTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "xrootd_oss_write_time_seconds",
		Help:    "The time taken for write operations on the OSS",
		Buckets: TimeHistogramBuckets,
	})

	OssPgWriteTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "xrootd_oss_pgwrite_time_seconds",
		Help:    "The time taken for page write operations on the OSS",
		Buckets: TimeHistogramBuckets,
	})

	OssDirlistTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "xrootd_oss_dirlist_time_seconds",
		Help:    "The time taken for directory list operations on the OSS",
		Buckets: TimeHistogramBuckets,
	})

	OssStatTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "xrootd_oss_stat_time_seconds",
		Help:    "The time taken for stat operations on the OSS",
		Buckets: TimeHistogramBuckets,
	})

	OssTruncateTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "xrootd_oss_truncate_time_seconds",
		Help:    "The time taken for truncate operations on the OSS",
		Buckets: TimeHistogramBuckets,
	})

	OssUnlinkTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "xrootd_oss_unlink_time_seconds",
		Help:    "The time taken for unlink operations on the OSS",
		Buckets: TimeHistogramBuckets,
	})

	OssRenameTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "xrootd_oss_rename_time_seconds",
		Help:    "The time taken for rename operations on the OSS",
		Buckets: TimeHistogramBuckets,
	})

	OssChmodTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "xrootd_oss_chmod_time_seconds",
		Help:    "The time taken for chmod operations on the OSS",
		Buckets: TimeHistogramBuckets,
	})

	OssSlowOpenTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "xrootd_oss_slow_open_time_seconds",
		Help:    "The time taken for slow open operations on the OSS",
		Buckets: TimeHistogramBuckets,
	})

	OssSlowReadTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "xrootd_oss_slow_read_time_seconds",
		Help:    "The time taken for slow read operations on the OSS",
		Buckets: TimeHistogramBuckets,
	})

	OssSlowReadvTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "xrootd_oss_slow_readv_time_seconds",
		Help:    "The time taken for slow readv operations on the OSS",
		Buckets: TimeHistogramBuckets,
	})

	OssSlowPgReadTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "xrootd_oss_slow_pgread_time_seconds",
		Help:    "The time taken for slow page read operations on the OSS",
		Buckets: TimeHistogramBuckets,
	})

	OssSlowWriteTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "xrootd_oss_slow_write_time_seconds",
		Help:    "The time taken for slow write operations on the OSS",
		Buckets: TimeHistogramBuckets,
	})

	OssSlowPgWriteTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "xrootd_oss_slow_pgwrite_time_seconds",
		Help:    "The time taken for slow page write operations on the OSS",
		Buckets: TimeHistogramBuckets,
	})

	OssSlowDirlistTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "xrootd_oss_slow_dirlist_time_seconds",
		Help:    "The time taken for slow directory list operations on the OSS",
		Buckets: TimeHistogramBuckets,
	})

	OssSlowStatTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "xrootd_oss_slow_stat_time_seconds",
		Help:    "The time taken for slow stat operations on the OSS",
		Buckets: TimeHistogramBuckets,
	})

	OssSlowTruncateTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "xrootd_oss_slow_truncate_time_seconds",
		Help:    "The time taken for slow truncate operations on the OSS",
		Buckets: TimeHistogramBuckets,
	})

	OssSlowUnlinkTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "xrootd_oss_slow_unlink_time_seconds",
		Help:    "The time taken for slow unlink operations on the OSS",
		Buckets: TimeHistogramBuckets,
	})

	OssSlowRenameTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "xrootd_oss_slow_rename_time_seconds",
		Help:    "The time taken for slow rename operations on the OSS",
		Buckets: TimeHistogramBuckets,
	})

	OssSlowChmodTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "xrootd_oss_slow_chmod_time_seconds",
		Help:    "The time taken for slow chmod operations on the OSS",
		Buckets: TimeHistogramBuckets,
	})

	CPUUtilization = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xrootd_cpu_utilization",
		Help: "CPU utilization of the XRootD server",
	})

	S3CacheBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "xrootd_s3_cache_bytes_total",
		Help: "Bytes transferred by the S3 cache plugin.",
	}, []string{"type"})

	S3CacheHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "xrootd_s3_cache_hits_total",
		Help: "Number of cache hits, partial hits, or misses.",
	}, []string{"type"})

	S3CacheRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "xrootd_s3_cache_requests_total",
		Help: "Number of cache requests.",
	}, []string{"type"})

	S3CacheErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_s3_cache_errors_total",
		Help: "Number of errors encountered by the S3 cache plugin.",
	})

	S3CacheRequestSeconds = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "xrootd_s3_cache_request_seconds_total",
		Help: "Total time spent in S3 requests.",
	}, []string{"type"})

	// Xrdcl Caching/Prefetching client statistics
	XrdclFilePrefetchCount = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_xrdcl_prefetch_count_total",
		Help: "Total number of prefetches started.",
	})
	XrdclFilePrefetchExpired = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_xrdcl_prefetch_expired_total",
		Help: "Total number of prefetches that expired.",
	})
	XrdclFilePrefetchFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_xrdcl_prefetch_failed_total",
		Help: "Total number of prefetches that failed.",
	})
	XrdclFilePrefetchReadsHit = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_xrdcl_prefetch_reads_hit_total",
		Help: "Total number of successful reads from prefetch buffer.",
	})
	XrdclFilePrefetchReadsMiss = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_xrdcl_prefetch_reads_miss_total",
		Help: "Total number of reads that missed the prefetch buffer.",
	})
	XrdclFilePrefetchBytesUsed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_xrdcl_prefetch_bytes_used_total",
		Help: "Total number of bytes served from prefetch.",
	})
	XrdclQueueProduced = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_xrdcl_queue_produced_total",
		Help: "Total number of HTTP requests placed into the queue.",
	})
	XrdclQueueConsumed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_xrdcl_queue_consumed_total",
		Help: "Total number of HTTP requests read from the queue.",
	})
	XrdclQueuePending = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xrootd_xrdcl_queue_pending",
		Help: "Number of pending HTTP requests in the queue.",
	})
	XrdclQueueRejected = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_xrdcl_queue_rejected_total",
		Help: "Total number of HTTP requests rejected due to overload.",
	})
	XrdclWorkerOldestOp = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xrootd_xrdcl_worker_oldest_op_timestamp_seconds",
		Help: "Timestamp of the oldest operation in any of the worker threads.",
	})
	XrdclWorkerOldestCycle = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xrootd_xrdcl_worker_oldest_cycle_timestamp_seconds",
		Help: "Timestamp of the oldest event loop completion in any of the worker threads.",
	})
	XrdclHTTPRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "xrootd_xrdcl_http_requests_total",
		Help: "Statistics about HTTP requests.",
	}, []string{"verb", "status", "type"})
	XrdclHTTPRequestDuration = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "xrootd_xrdcl_http_request_duration_seconds_total",
		Help: "Total duration of HTTP requests.",
	}, []string{"verb", "status", "type"})
	XrdclHTTPBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "xrootd_xrdcl_http_bytes_total",
		Help: "Bytes transferred for HTTP requests.",
	}, []string{"verb", "status"})
	XrdclConncall = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "xrootd_xrdcl_conncall_total",
		Help: "Statistics about connection calls.",
	}, []string{"type"})

	lastStats        SummaryStat
	lastOssStats     OSSStatsGs
	lastS3CacheStats OssS3CacheGs
	lastXrdCurlStats struct {
		File    XrdCurlFileStats
		Queues  XrdCurlQueueStats
		Workers map[string]float64
	}

	procState = processUtilizationState{}

	lastTotalIO  int     // The last total IO value
	lastWaitTime float64 // The last IO wait time

	// Maps the connection identifier with a user record
	sessions = ttlcache.New[UserId, UserRecord](ttlcache.WithTTL[UserId, UserRecord](24 * time.Hour))
	// Maps a userid to a connection identifier.  NOTE: due to https://github.com/xrootd/xrootd/issues/2133,
	// this may not be a unique map.
	userids = ttlcache.New[XrdUserId, UserId](ttlcache.WithTTL[XrdUserId, UserId](24 * time.Hour))
	// Maps a file identifier with a file record
	transfers    = ttlcache.New[FileId, FileRecord](ttlcache.WithTTL[FileId, FileRecord](24 * time.Hour))
	monitorPaths []PathList
)

var allowedEvents = map[string]bool{OssStatsEvent: true, S3FileStatsEvent: true}

// Set up listening and parsing xrootd monitoring UDP packets into prometheus
//
// The `ctx` is the context for listening to server shutdown event in order to cleanup internal cache eviction
func ConfigureMonitoring(ctx context.Context, egrp *errgroup.Group) (int, error) {
	monitorPaths = make([]PathList, 0)
	for _, monpath := range param.Monitoring_AggregatePrefixes.GetStringSlice() {
		monitorPaths = append(monitorPaths, PathList{Paths: strings.Split(path.Clean(monpath), "/")})
	}

	lower := param.Monitoring_PortLower.GetInt()
	higher := param.Monitoring_PortHigher.GetInt()

	addr := net.UDPAddr{IP: net.ParseIP("127.0.0.1")}
	var conn *net.UDPConn
	var err error
	for portAttempt := lower; portAttempt < higher; portAttempt++ {
		addr.Port = portAttempt
		conn, err = net.ListenUDP("udp", &addr)
		if err == nil {
			break
		}
	}
	if conn == nil {
		if err != nil {
			return -1, err
		}
		return -1, errors.New("Failed to create a UDP listening socket for monitoring")
	}

	// Set the read buffer size to 1 MB
	err = conn.SetReadBuffer(1024 * 1024)
	if err != nil {
		return -1, err
	}

	// Start ttl cache automatic eviction of expired items
	go sessions.Start()
	go userids.Start()
	go transfers.Start()

	// Stop automatic eviction at shutdown
	egrp.Go(func() error {
		<-ctx.Done()
		conn.Close() // This will cause an net.ErrClosed in the goroutine below
		sessions.Stop()
		userids.Stop()
		transfers.Stop()
		log.Infoln("Xrootd metrics cache eviction has been stopped")
		return nil
	})

	enableHandlePacket := param.Xrootd_EnableLocalMonitoring.GetBool()

	go func() {
		// if the shoveler is not enabled, then we need to listen to the UDP packets coming from XRootD
		// if the shoveler is enabled, then the shoveler will listen to XRootD and update the metrics
		if !param.Shoveler_Enable.GetBool() {
			var buf [65536]byte
			for {
				// TODO: actually parse the UDP packets
				plen, _, err := conn.ReadFromUDP(buf[:])
				if errors.Is(err, net.ErrClosed) {
					return
				} else if err != nil {
					log.Errorln("Failed to read from UDP connection while aggregating monitoring packet from XRootD:", err)
					continue
				}
				// TODO: Remove this metric (the line directly below)
				// The renamed metric was added in v7.16
				PacketsReceived.Inc()
				PacketsReceivedTotal.Inc()
				if !enableHandlePacket {
					continue
				}
				if err = handlePacket(buf[:plen]); err != nil {
					log.Errorln("Pelican failed to handle monitoring packet received from XRootD:", err)
				}
			}
		}
	}()
	return addr.Port, nil
}

func computePrefix(inputPath string, monitorPaths []PathList) string {
	if len(monitorPaths) == 0 {
		return "/"
	}

	segments := strings.Split(path.Clean(inputPath), "/")

	maxlen := 0
	for _, pathList := range monitorPaths {
		if len(pathList.Paths) > len(segments) {
			continue
		}
		for idx, segment := range pathList.Paths {
			if len(segments) <= idx {
				break
			}
			if segments[idx] != segment && segment != "*" {
				break
			}
			if idx > maxlen {
				maxlen = idx
			}
		}
	}
	if maxlen == 0 {
		return "/"
	}

	result := ""
	for idx := 1; idx < maxlen+1; idx++ {
		result += "/" + segments[idx]
	}
	return path.Clean(result)
}

func GetSIDRest(info []byte) (xrdUserId XrdUserId, rest string, err error) {
	log.Debugln("GetSIDRest inputs:", string(info))
	infoSplit := strings.SplitN(string(info), "\n", 2)
	if len(infoSplit) == 1 {
		err = errors.New("Unable to parse SID")
		return
	}
	rest = infoSplit[1]

	xrdUserId, err = ParseXrdUserId(infoSplit[0])
	return
}

func ParseXrdUserId(userid string) (xrdUserId XrdUserId, err error) {
	// Expected format: prot/user.id:sid@clientHost
	sidInfo := strings.SplitN(userid, ":", 2)
	if len(sidInfo) == 1 {
		err = errors.New("Unable to parse valid user ID - missing ':' delimiter")
		return
	}

	// Parse server ID and client hostname,
	// Form: 82215220691948@localhost
	sidAtHostname := sidInfo[1]
	sidAtHostnameInfo := strings.SplitN(sidAtHostname, "@", 2)
	if len(sidAtHostnameInfo) == 1 {
		err = errors.New("Unable to parse valid server ID - missing '@' delimiter")
		return
	}
	sid, err := strconv.Atoi(sidAtHostnameInfo[0])
	if err != nil {
		err = errors.Wrap(err, "Unable to parse valid server ID")
		return
	}

	// Parse prot/user.id
	protUserIdInfo := strings.SplitN(sidInfo[0], "/", 2)
	if len(protUserIdInfo) == 1 {
		err = errors.New("Unable to parse user ID - missing '/' delimiter")
		return
	}

	// Parse user.id; assume user may contain multiple '.' characters
	lastIdx := strings.LastIndex(protUserIdInfo[1], ".")
	if lastIdx == -1 {
		err = errors.New("Unable to parse user ID - missing '.' delimiter")
		return
	}
	pid, err := strconv.Atoi(protUserIdInfo[1][lastIdx+1 : len(protUserIdInfo[1])])
	if err != nil {
		err = errors.Wrap(err, "Unable to parse PID as integer")
		return
	}

	// Finally, fill in our userid struct
	xrdUserId.Prot = protUserIdInfo[0]
	xrdUserId.User = protUserIdInfo[1][:lastIdx]
	xrdUserId.Pid = pid
	xrdUserId.Sid = sid
	xrdUserId.Host = string(sidAtHostnameInfo[1])
	return
}

func ParseTokenAuth(tokenauth string) (userId UserId, record UserRecord, err error) {
	record.AuthenticationProtocol = "ztn"
	foundUc := false
	for _, pair := range strings.Split(tokenauth, "&") {
		keyVal := strings.SplitN(pair, "=", 2)
		if len(keyVal) != 2 {
			continue
		}
		switch keyVal[0] {
		case "Uc":
			var id int
			id, err = strconv.Atoi(keyVal[1])
			if err != nil {
				err = errors.Wrap(err, "Unable to parse user ID to integer")
				return
			}
			if id < 0 || id > math.MaxUint32 {
				err = errors.Errorf("Provided ID, %d, is not a valid uint32", id)
				return
			}
			userId.Id = uint32(id)
			foundUc = true
		case "s":
			record.DN = keyVal[1]
		case "un":
			record.User = keyVal[1]
		case "o":
			record.Org = keyVal[1]
		case "r":
			record.Role = keyVal[1]
		case "g":
			record.Groups = strings.Split(keyVal[1], " ")
		}
	}
	if !foundUc {
		err = errors.New("The user ID was not provided in the token record")
		return
	}
	return
}

func ParseFileHeader(packet []byte) (XrdXrootdMonFileHdr, error) {
	if len(packet) < 8 {
		return XrdXrootdMonFileHdr{}, fmt.Errorf("passed header of size %v which is below the minimum header size of 8 bytes", len(packet))
	}
	fileHdr := XrdXrootdMonFileHdr{
		RecType: recTval(packet[0]),
		RecFlag: packet[1],
		RecSize: int16(binary.BigEndian.Uint16(packet[2:4])),
		FileId:  binary.BigEndian.Uint32(packet[4:8]),
		UserId:  binary.BigEndian.Uint32(packet[4:8]),
		NRecs0:  int16(binary.BigEndian.Uint16(packet[4:6])),
		NRecs1:  int16(binary.BigEndian.Uint16(packet[6:8])),
	}
	return fileHdr, nil
}

func NullTermToString(nullTermBytes []byte) (str string) {
	idx := bytes.IndexByte(nullTermBytes, '\x00')
	if idx == -1 {
		return ""
	}
	return string(nullTermBytes[0:idx])
}

func handlePacket(packet []byte) error {
	if len(packet) < 8 {
		return errors.New("Packet is too small to be valid XRootD monitoring packet")
	}

	// XML '<' character indicates a summary packet
	if len(packet) > 0 && packet[0] == '<' {
		return HandleSummaryPacket(packet)
	}

	if len(packet) > 0 && packet[0] == '{' {
		cleanPacket := bytes.Trim(packet, "\x00")
		blobs := bytes.Split(cleanPacket, []byte("\n"))
		var header DfltHdr
		err := json.Unmarshal(blobs[0], &header)
		if err != nil {
			return errors.Wrap(err, "failed to parse JSON monitoring packet")
		}
		// OSS Packet
		if header.Gs.Type == "O" {
			log.Trace("handlePacket: Received a g-stream OSS packet")
			if len(blobs) < 2 {
				return errors.New("Packet is too small to be valid g-stream OSS packet")
			}
			return handleOSSPacket(blobs[1:]) // Skip the header
		}

		if header.Gs.Type == "R" { // Throttle Packet
			log.Trace("handlePacket: Received a g-stream R packet")
			if len(blobs) < 2 {
				return errors.New("packet is too small to be valid g-stream R packet")
			}
			return handleThrottlePacket(blobs[1:]) // Skip the header
		}
		return nil
	}

	var header XrdXrootdMonHeader
	header.Code = packet[0]
	header.Pseq = packet[1]
	header.Plen = binary.BigEndian.Uint16(packet[2:4])
	header.Stod = int32(binary.BigEndian.Uint32(packet[4:8]))

	// For =, p, and x record-types, this is always 0
	// For i, T, u, and U , this is a connection ID
	// For d, this is a file ID.
	dictid := binary.BigEndian.Uint32(packet[8:12])

	switch header.Code {
	case 'd':
		log.Trace("handlePacket: Received a file-open packet")
		if len(packet) < 12 {
			return errors.New("Packet is too small to be valid file-open packet")
		}
		fileid := FileId{Id: dictid}
		xrdUserId, rest, err := GetSIDRest(packet[12:])
		if err != nil {
			return errors.Wrapf(err, "Failed to parse XRootD monitoring packet")
		}
		path := computePrefix(rest, monitorPaths)
		if useridItem := userids.Get(xrdUserId); useridItem != nil {
			transfers.Set(fileid, FileRecord{UserId: useridItem.Value(), Path: path}, ttlcache.DefaultTTL)
		}
	case 'f':
		log.Trace("handlePacket: Received a f-stream packet")
		// sizeof(XrdXrootdMonHeader) + sizeof(XrdXrootdMonFileTOD)
		if len(packet) < 8+24 {
			return errors.New("Packet is too small to be a valid f-stream packet")
		}
		firstHeaderSize := binary.BigEndian.Uint16(packet[10:12])
		if firstHeaderSize < 24 {
			return fmt.Errorf("first entry in f-stream packet is %v bytes, smaller than the minimum XrdXrootdMonFileTOD size of 24 bytes", firstHeaderSize)
		}
		offset := uint32(firstHeaderSize + 8)
		bytesRemain := header.Plen - uint16(offset)
		for bytesRemain > 0 {
			fileHdr, err := ParseFileHeader(packet[offset : offset+8])
			if err != nil {
				return err
			}
			switch fileHdr.RecType {
			case isClose: // XrdXrootdMonFileHdr::isClose
				log.Traceln("Received a f-stream file-close packet of size ",
					fileHdr.RecSize)
				fileId := FileId{Id: fileHdr.FileId}
				xferRecord := transfers.Get(fileId)
				transfers.Delete(fileId)
				labels := prometheus.Labels{
					"path":    "/",
					"ap":      "",
					"dn":      "",
					"role":    "",
					"org":     "",
					"proj":    "",
					"network": "",
				}
				var oldReadvSegs uint64 = 0
				var oldReadOps uint32 = 0
				var oldReadvOps uint32 = 0
				var oldWriteOps uint32 = 0
				var oldReadBytes uint64 = 0
				var oldReadvBytes uint64 = 0
				var oldWriteBytes uint64 = 0
				if xferRecord != nil {
					userRecord := sessions.Get(xferRecord.Value().UserId)
					labels["path"] = xferRecord.Value().Path
					if userRecord != nil {
						maskedIP, ok := utils.ExtractAndMaskIP(userRecord.Value().XrdUserId.Host)
						if !ok {
							log.Warning(fmt.Sprintf("Failed to mask IP address: %s", maskedIP))
						} else {
							labels["network"] = maskedIP
						}
						labels["ap"] = userRecord.Value().AuthenticationProtocol
						labels["dn"] = userRecord.Value().DN
						labels["role"] = userRecord.Value().Role
						labels["org"] = userRecord.Value().Org
						labels["proj"] = userRecord.Value().Project
					}
					oldReadvSegs = xferRecord.Value().ReadvSegs
					oldReadOps = xferRecord.Value().ReadOps
					oldReadvOps = xferRecord.Value().ReadvOps
					oldWriteOps = xferRecord.Value().WriteOps
					oldReadBytes = xferRecord.Value().ReadBytes
					oldReadvBytes = xferRecord.Value().ReadvBytes
					oldWriteBytes = xferRecord.Value().WriteBytes
				}
				if fileHdr.RecFlag&0x02 == 0x02 { // XrdXrootdMonFileHdr::hasOPS
					// sizeof(XrdXrootdMonFileHdr) + sizeof(XrdXrootdMonStatXFR)
					opsOffset := uint32(8 + 24)
					// TODO: Remove this metric (the 2 lines directly below)
					// The renamed metric was added in v7.16
					counter := TransferReadvSegs.With(labels)
					counter.Add(float64(int64(binary.BigEndian.Uint64(
						packet[offset+opsOffset+16:offset+opsOffset+24]) -
						oldReadvSegs)))
					counter = TransferReadvSegsTotal.With(labels)
					counter.Add(float64(int64(binary.BigEndian.Uint64(
						packet[offset+opsOffset+16:offset+opsOffset+24]) -
						oldReadvSegs)))

					labels["type"] = "read"
					// TODO: Remove this metric (the 2 lines directly below)
					// The renamed metric was added in v7.16
					counter = TransferOps.With(labels)
					counter.Add(float64(int32(binary.BigEndian.Uint32(
						packet[offset+opsOffset:offset+opsOffset+4]) -
						oldReadOps)))
					counter = TransferOpsTotal.With(labels)
					counter.Add(float64(int32(binary.BigEndian.Uint32(
						packet[offset+opsOffset:offset+opsOffset+4]) -
						oldReadOps)))

					labels["type"] = "readv"
					// TODO: Remove this metric (the 2 lines directly below)
					// The renamed metric was added in v7.16
					counter = TransferOps.With(labels)
					counter.Add(float64(int32(binary.BigEndian.Uint32(
						packet[offset+opsOffset+4:offset+opsOffset+8]) -
						oldReadvOps)))
					counter = TransferOpsTotal.With(labels)
					counter.Add(float64(int32(binary.BigEndian.Uint32(
						packet[offset+opsOffset+4:offset+opsOffset+8]) -
						oldReadvOps)))

					labels["type"] = "write"
					// TODO: Remove this metric (the 2 lines directly below)
					// The renamed metric was added in v7.16
					counter = TransferOps.With(labels)
					counter.Add(float64(int32(binary.BigEndian.Uint32(
						packet[offset+opsOffset+8:offset+opsOffset+12]) -
						oldWriteOps)))
					counter = TransferOpsTotal.With(labels)
					counter.Add(float64(int32(binary.BigEndian.Uint32(
						packet[offset+opsOffset+8:offset+opsOffset+12]) -
						oldWriteOps)))
				}
				xfrOffset := uint32(8) // sizeof(XrdXrootdMonFileHdr)
				labels["type"] = "read"
				counter := TransferBytes.With(labels)
				counter.Add(float64(int64(binary.BigEndian.Uint64(
					packet[offset+xfrOffset:offset+xfrOffset+8]) -
					oldReadBytes)))
				labels["type"] = "readv"
				counter = TransferBytes.With(labels)
				counter.Add(float64(int64(binary.BigEndian.Uint64(
					packet[offset+xfrOffset+8:offset+xfrOffset+16]) -
					oldReadvBytes)))
				labels["type"] = "write"
				counter = TransferBytes.With(labels)
				counter.Add(float64(int64(binary.BigEndian.Uint64(
					packet[offset+xfrOffset+16:offset+xfrOffset+24]) -
					oldWriteBytes)))

				logFields := log.Fields{
					"timestamp":    time.Now().Format(time.RFC3339),
					"filePath":     labels["path"],
					"authProtocol": labels["ap"],
					"dn":           labels["dn"],
					"project":      labels["proj"],
					"org":          labels["org"],
					"role":         labels["role"],
					"network":      labels["network"],
					"type":         labels["type"],
				}
				log.WithFields(logFields).Trace("XRootD file closed")
			case isOpen: // XrdXrootdMonFileHdr::isOpen
				log.Trace("MonPacket: Received a f-stream file-open packet")
				fileid := FileId{Id: fileHdr.FileId}
				path := ""
				userId := UserId{}
				if fileHdr.RecFlag&0x01 == 0x01 { // hasLFN
					lfnSize := uint32(fileHdr.RecSize - 20)
					lfn := NullTermToString(packet[offset+20 : offset+lfnSize+20])
					// path has been defined
					path = computePrefix(lfn, monitorPaths)
					log.Tracef("MonPacket: User LFN %v matches prefix %v",
						lfn, path)
					// UserId is part of LFN
					userId = UserId{Id: binary.BigEndian.Uint32(packet[offset+16 : offset+20])}
				}
				transfers.Set(fileid, FileRecord{UserId: userId, Path: path},
					ttlcache.DefaultTTL)

				logFields := log.Fields{
					"timestamp":    time.Now().Format(time.RFC3339),
					"filePath":     path,
					"authProtocol": "",
					"dn":           "",
					"project":      "",
					"org":          "",
					"role":         "",
					"network":      "",
					"type":         "open",
				}

				userRecord := sessions.Get(userId)
				if userRecord != nil {
					maskedIP, ok := utils.ExtractAndMaskIP(userRecord.Value().XrdUserId.Host)
					if !ok {
						log.Warning(fmt.Sprintf("Failed to mask IP address: %s", maskedIP))
					} else {
						logFields["network"] = maskedIP
					}
					logFields["authProtocol"] = userRecord.Value().AuthenticationProtocol
					logFields["dn"] = userRecord.Value().DN
					logFields["role"] = userRecord.Value().Role
					logFields["org"] = userRecord.Value().Org
					logFields["project"] = userRecord.Value().Project
				}
				log.WithFields(logFields).Trace("XRootD file opened")
			case isTime: // XrdXrootdMonFileHdr::isTime
				log.Trace("MonPacket: Received a f-stream time packet")
			case isXfr: // XrdXrootdMonFileHdr::isXfr
				log.Trace("MonPacket: Received a f-stream transfer packet")
				// NOTE: There's a lot to do here.  These records would allow us to
				// capture partial file transfers or emulate a close on timeout.
				// For now, we'll record the data but don't use it.
				fileid := FileId{Id: fileHdr.FileId}
				item := transfers.Get(fileid)
				var record FileRecord
				readBytes := binary.BigEndian.Uint64(packet[offset+8 : offset+16])
				readvBytes := binary.BigEndian.Uint64(packet[offset+16 : offset+24])
				writeBytes := binary.BigEndian.Uint64(packet[offset+24 : offset+32])

				labels := prometheus.Labels{
					"path":    "/",
					"ap":      "",
					"dn":      "",
					"role":    "",
					"org":     "",
					"proj":    "",
					"network": "",
				}

				logFields := log.Fields{
					"timestamp":    time.Now().Format(time.RFC3339),
					"filePath":     "/",
					"authProtocol": "",
					"dn":           "",
					"project":      "",
					"org":          "",
					"role":         "",
					"network":      "",
					"type":         "",
				}

				if item != nil {
					record = item.Value()
					userRecord := sessions.Get(record.UserId)
					labels["path"] = record.Path
					logFields["filePath"] = record.Path
					if userRecord != nil {
						maskedIP, ok := utils.ExtractAndMaskIP(userRecord.Value().XrdUserId.Host)
						if !ok {
							log.Warning(fmt.Sprintf("Failed to mask IP address: %s", maskedIP))
						} else {
							labels["network"] = maskedIP
						}
						labels["ap"] = userRecord.Value().AuthenticationProtocol
						logFields["authProtocol"] = userRecord.Value().AuthenticationProtocol
						labels["dn"] = userRecord.Value().DN
						logFields["dn"] = userRecord.Value().DN
						labels["role"] = userRecord.Value().Role
						logFields["role"] = userRecord.Value().Role
						labels["org"] = userRecord.Value().Org
						logFields["org"] = userRecord.Value().Org
						labels["proj"] = userRecord.Value().Project
						logFields["project"] = userRecord.Value().Project
					}
				}

				// We record those metrics to make sure they are properly populated with initial
				// values, or the file close handler will only populate them by the difference, not
				// the total
				labels["type"] = "read"
				counter := TransferBytes.With(labels)
				incBy := int64(readBytes - record.ReadBytes)
				if incBy >= 0 {
					counter.Add(float64(incBy))
				} else {
					log.Debug("File-transfer ReadBytes is less than previous value")
				}
				labels["type"] = "readv"
				counter = TransferBytes.With(labels)
				incBy = int64(readvBytes - record.ReadvBytes)
				if incBy >= 0 {
					counter.Add(float64(incBy))
				} else {
					log.Debug("File-transfer ReadVBytes is less than previous value")
				}
				labels["type"] = "write"
				counter = TransferBytes.With(labels)
				incBy = int64(writeBytes - record.WriteBytes)
				if incBy >= 0 {
					counter.Add(float64(incBy))
				} else {
					log.Debug("File-transfer WriteByte is less than previous value")
				}
				record.ReadBytes = readBytes
				record.ReadvBytes = readvBytes
				record.WriteBytes = writeBytes
				transfers.Set(fileid, record, ttlcache.DefaultTTL)

				logFields["type"] = labels["type"]
				log.WithFields(logFields).Trace("XRootD file transfer")

			case isDisc: // XrdXrootdMonFileHdr::isDisc
				log.Trace("MonPacket: Received a f-stream disconnect packet")
				userId := UserId{Id: fileHdr.UserId}
				item, found := sessions.GetAndDelete(userId)
				if found {
					userids.Delete(item.Value().XrdUserId)
				}
			default:
				log.Debug("MonPacket: Received an unhandled file monitoring packet "+
					"of type ", fileHdr.RecType)
			}

			bytesRemain -= uint16(fileHdr.RecSize)
			offset += uint32(fileHdr.RecSize)
		}
	case 'g':
		log.Trace("handlePacket: Received a g-stream packet")
		if len(packet) < 8+16 {
			return errors.New("Packet is too small to be a valid g-stream packet")
		}
		gs := XrdXrootdMonGS{
			Hdr:  header,
			TBeg: int(binary.BigEndian.Uint32(packet[8:12])),
			TEnd: int(binary.BigEndian.Uint32(packet[12:16])),
			SID:  int64(binary.BigEndian.Uint64(packet[16:24])),
		}
		// Extract the provider’s identifier
		providerID := (gs.SID >> XROOTD_MON_PIDSHFT) & XROOTD_MON_PIDMASK
		detail := NullTermToString(packet[24:])
		strJsons := strings.Split(detail, "\n")
		if providerID == 'C' { // pfc: Cache monitoring info
			log.Trace("handlePacket: Received g-stream packet is from cache")
			aggCacheStat := make(map[string]*CacheAccessStat)
			for _, js := range strJsons {
				cacheStat := CacheGS{}
				log.Trace("handlePacket: Received cache stat json: ", string(js))
				if err := json.Unmarshal([]byte(js), &cacheStat); err != nil {
					return errors.Wrap(err, "failed to parse cache stat json. Raw data is "+string(js))
				}

				prefix := computePrefix(cacheStat.Lfn, monitorPaths)
				if aggCacheStat[prefix] == nil {
					aggCacheStat[prefix] = &CacheAccessStat{
						Hit:      cacheStat.ByteHit,
						Miss:     cacheStat.ByteMiss,
						Bypass:   cacheStat.ByteBypass,
						Prefetch: cacheStat.BytePrefetch,
						ToDisk:   cacheStat.ByteToDisk,
					}
				} else {
					aggCacheStat[prefix].Hit += cacheStat.ByteHit
					aggCacheStat[prefix].Miss += cacheStat.ByteMiss
					aggCacheStat[prefix].Bypass += cacheStat.ByteBypass
					aggCacheStat[prefix].Prefetch += cacheStat.BytePrefetch
					aggCacheStat[prefix].ToDisk += cacheStat.ByteToDisk
				}
			}
			for prefix, stat := range aggCacheStat {
				// For hit, miss, bypass, each packet only records the buffer
				// between last sent and now, so we need to add them
				CacheAccess.WithLabelValues(prefix, "hit").Add(float64(stat.Hit))
				CacheAccess.WithLabelValues(prefix, "miss").Add(float64(stat.Miss))
				CacheAccess.WithLabelValues(prefix, "bypass").Add(float64(stat.Bypass))
				CacheAccess.WithLabelValues(prefix, "prefetch").Add(float64(stat.Prefetch))
				CacheAccess.WithLabelValues(prefix, "to_disk").Add(float64(stat.ToDisk))
			}
		}

	case 'i':
		log.Trace("handlePacket: Received an appinfo packet")
		infoSize := uint32(header.Plen - 12)
		if xrdUserId, appinfo, err := GetSIDRest(packet[12 : 12+infoSize]); err == nil {
			item := userids.Get(xrdUserId)
			if item != nil {
				userId := item.Value()
				project := utils.ExtractProjectFromUserAgent([]string{appinfo})
				item, found := sessions.GetOrSet(userId, UserRecord{Project: project, XrdUserId: xrdUserId}, ttlcache.WithTTL[UserId, UserRecord](ttlcache.DefaultTTL))
				if found {
					existingRec := item.Value()
					existingRec.Project = project
					existingRec.XrdUserId = xrdUserId
					sessions.Set(userId, existingRec, ttlcache.DefaultTTL)
				}
			}
		} else {
			return err
		}
	case 'u':
		log.Trace("handlePacket: Received a user login packet")
		infoSize := uint32(header.Plen - 12)
		if xrdUserId, auth, err := GetSIDRest(packet[12 : 12+infoSize]); err == nil {
			var record UserRecord
			for _, pair := range strings.Split(auth, "&") {
				keyVal := strings.SplitN(pair, "=", 2)
				if len(keyVal) != 2 {
					continue
				}
				switch keyVal[0] {
				case "n":
					record.DN = keyVal[1]
				case "p":
					record.AuthenticationProtocol = keyVal[1]
				case "o":
					record.Org = keyVal[1]
				case "r":
					record.Role = keyVal[1]
				case "g":
					record.Groups = strings.Split(keyVal[1], " ")
				}
			}
			if len(record.AuthenticationProtocol) > 0 {
				record.User = xrdUserId.User
			}
			record.XrdUserId = xrdUserId
			sessions.Set(UserId{Id: dictid}, record, ttlcache.DefaultTTL)
			userids.Set(xrdUserId, UserId{Id: dictid}, ttlcache.DefaultTTL)
		} else {
			return err
		}
	case 'T':
		log.Trace("handlePacket: Received a token info packet")
		infoSize := uint32(header.Plen - 12)
		if xrdUserId, tokenauth, err := GetSIDRest(packet[12 : 12+infoSize]); err == nil {
			userId, userRecord, err := ParseTokenAuth(tokenauth)
			if err != nil {
				return err
			}
			userRecord.XrdUserId = xrdUserId
			sessions.Set(userId, userRecord, ttlcache.DefaultTTL)
		} else {
			return err
		}
	default:
		log.Debugf("handlePacket: Received an unhandled monitoring packet of type %v", header.Code)
	}

	return nil

}

// Unlike the highly-compressed binary format that is the detailed monitoring, the summary monitoring
// is a mostly-compliant chunk of XML.  I copy below the pretty-printed version of a sample packet:
/*
   <statistics tod="1687524138" ver="v5.2.0" src="hcc-briantest7.unl.edu:8443" tos="1687523538" pgm="xrootd" ins="anon" pid="3852923" site="hcc-briantest7.unl.edu">
  <stats id="info">
    <host>hcc-briantest7.unl.edu</host>
    <port>8443</port>
    <name>anon</name>
  </stats>
  <stats id="buff">
    <reqs>2</reqs>
    <mem>1049600</mem>
    <buffs>2</buffs>
    <adj>0</adj>
    <xlreqs>0</xlreqs>
    <xlmem>0</xlmem>
    <xlbuffs>0</xlbuffs>
  </stats>
  <stats id="link">
    <num>0</num>
    <maxn>1</maxn>
    <tot>1</tot>
    <in>474</in>
    <out>1117</out>
    <ctime>0</ctime>
    <tmo>0</tmo>
    <stall>0</stall>
    <sfps>0</sfps>
  </stats>
  <stats id="poll">
    <att>0</att>
    <en>1</en>
    <ev>1</ev>
    <int>0</int>
  </stats>
  <stats id="proc">
    <usr>
      <s>0</s>
      <u>42946</u>
    </usr>
    <sys>
      <s>0</s>
      <u>52762</u>
    </sys>
  </stats>
  <stats id="xrootd">
    <num>1</num>
    <ops>
      <open>1</open>
      <rf>0</rf>
      <rd>1</rd>
      <pr>0</pr>
      <rv>0</rv>
      <rs>0</rs>
      <wv>0</wv>
      <ws>0</ws>
      <wr>0</wr>
      <sync>0</sync>
      <getf>0</getf>
      <putf>0</putf>
      <misc>2</misc>
    </ops>
    <sig>
      <ok>0</ok>
      <bad>0</bad>
      <ign>0</ign>
    </sig>
    <aio>
      <num>0</num>
      <max>0</max>
      <rej>0</rej>
    </aio>
    <err>0</err>
    <rdr>0</rdr>
    <dly>0</dly>
    <lgn>
      <num>0</num>
      <af>0</af>
      <au>0</au>
      <ua>0</ua>
    </lgn>
  </stats>
  <stats id="ofs">
    <role>server</role>
    <opr>0</opr>
    <opw>0</opw>
    <opp>0</opp>
    <ups>0</ups>
    <han>0</han>
    <rdr>0</rdr>
    <bxq>0</bxq>
    <rep>0</rep>
    <err>0</err>
    <dly>0</dly>
    <sok>0</sok>
    <ser>0</ser>
    <tpc>
      <grnt>0</grnt>
      <deny>0</deny>
      <err>0</err>
      <exp>0</exp>
    </tpc>
  </stats>
  <stats id="oss" v="2">
    <paths>1<stats id="0"><lp>"/test"</lp><rp>"/run/user/1221/pelican/export/test"</rp><tot>1562624</tot><free>1529424</free><ino>786432</ino><ifr>786405</ifr></stats></paths>
    <space>0</space>
  </stats>
  <stats id="sched">
    <jobs>188</jobs>
    <inq>0</inq>
    <maxinq>5</maxinq>
    <threads>7</threads>
    <idle>5</idle>
    <tcr>7</tcr>
    <tde>0</tde>
    <tlimr>0</tlimr>
  </stats>
  <stats id="sgen">
    <as>0</as>
    <et>1</et>
    <toe>1687524138</toe>
  </stats>
</statistics>
*/

func HandleSummaryPacket(packet []byte) error {
	summaryStats := SummaryStatistics{}
	// The cache summary data has a typo where the <hit> tag contains a trailing bracet
	// the causes parsing error. This is a temp fix to correct it. Xrootd v5.7.0 will fix
	// this issue
	re, err := regexp.Compile(`></hits>`)
	if err != nil {
		return errors.Wrap(err, "error compiling regex")
	}

	correctedData := re.ReplaceAll(packet, []byte(`</hits>`))

	if err := xml.Unmarshal(correctedData, &summaryStats); err != nil {
		return errors.Wrap(err, "error unmarshalling summary packet")
	}

	log.Debug("Received a summary statistics packet")
	if summaryStats.Program != "xrootd" {
		// We only care about the xrootd summary packets
		return nil
	}
	for _, stat := range summaryStats.Stats {
		switch stat.Id {

		case LinkStat:
			// When stats tag has id="link", the following definitions are valid:
			// stat.Total: Connections since start-up.
			// stat.In: Bytes received
			// stat.Out: Bytes sent

			// Note that stat.Total is the total connections since the start-up of the service
			// So we just want to make sure here that no negative value is present
			incBy := float64(stat.Total - lastStats.Total)
			if stat.Total < lastStats.Total {
				incBy = float64(stat.Total)
			}
			Connections.Add(incBy)
			ConnectionsTotal.Add(incBy)
			lastStats.Total = stat.Total

			incBy = float64(stat.In - lastStats.In)
			if stat.In < lastStats.In {
				incBy = float64(stat.In)
			}
			BytesXfer.With(prometheus.Labels{"direction": "rx"}).Add(incBy)
			BytesXferTotal.With(prometheus.Labels{"direction": "rx"}).Add(incBy)
			lastStats.In = stat.In

			incBy = float64(stat.Out - lastStats.Out)
			if stat.Out < lastStats.Out {
				incBy = float64(stat.Out)
			}
			BytesXfer.With(prometheus.Labels{"direction": "tx"}).Add(incBy)
			BytesXferTotal.With(prometheus.Labels{"direction": "tx"}).Add(incBy)
			lastStats.Out = stat.Out
		case SchedStat:
			Threads.With(prometheus.Labels{"state": "idle"}).Set(float64(stat.Idle))
			Threads.With(prometheus.Labels{"state": "running"}).Set(float64(stat.Threads -
				stat.Idle))

			Queued.Set(float64(stat.Queued))
			LongestQueue.Set(float64(stat.LongestQueue))
			Jobs.Set(float64(stat.Jobs))
			// We have to do this exclusively for thread creations because the metric is not monotonic
			// See https://github.com/xrootd/xrootd/blob/f1de2038e0c5c10990769f5b7ff82200cc8c3d56/src/Xrd/XrdScheduler.cc#L700
			incBy := float64(stat.ThreadCreations - lastStats.ThreadCreations)
			if stat.ThreadCreations < lastStats.ThreadCreations {
				incBy = 0
			}
			ThreadCreations.Add(incBy)

			incBy = float64(stat.ThreadDestructions - lastStats.ThreadDestructions)
			if stat.ThreadDestructions < lastStats.ThreadDestructions {
				incBy = 0
			}
			ThreadDestructions.Add(incBy)

			incBy = float64(stat.ThreadLimitReached - lastStats.ThreadLimitReached)
			if stat.ThreadLimitReached < lastStats.ThreadLimitReached {
				incBy = 0
			}
			ThreadLimitReached.Add(incBy)

			lastStats.ThreadCreations = stat.ThreadCreations
			lastStats.ThreadDestructions = stat.ThreadDestructions
			lastStats.ThreadLimitReached = stat.ThreadLimitReached
		case OssStat: // Oss stat should only appear on origin servers
			for _, pathStat := range stat.Paths.Stats {
				noQuoteLp := strings.Replace(pathStat.Lp, "\"", "", 2)
				// pathStat.Total is in kilobytes but we want to standardize all data to bytes
				StorageVolume.With(prometheus.Labels{"ns": noQuoteLp, "type": "total", "server_type": "origin"}).
					Set(float64(pathStat.Total * 1024))
				StorageVolume.With(prometheus.Labels{"ns": noQuoteLp, "type": "free", "server_type": "origin"}).
					Set(float64(pathStat.Free * 1024))
			}
		case CacheStat:
			cacheStore := stat.Store
			StorageVolume.With(prometheus.Labels{"ns": "/cache", "type": "total", "server_type": "cache"}).
				Set(float64(cacheStore.Size))
			StorageVolume.With(prometheus.Labels{"ns": "/cache", "type": "free", "server_type": "cache"}).
				Set(float64(cacheStore.Size - cacheStore.Used))
		case ProcStat:
			procState.Lock()
			defer procState.Unlock()
			currentTime := time.Now()
			currentUserSeconds := float64(stat.ProcUser.Seconds) + float64(stat.ProcUser.MicroSeconds)/1e6
			currentSystemSeconds := float64(stat.ProcSystem.Seconds) + float64(stat.ProcSystem.MicroSeconds)/1e6

			// if this not is the first time we are receiving the proc stat, then we can
			// calculate the deltas since the last time we received the proc stat
			if !procState.lastUpdateTime.IsZero() {
				wallDelta := currentTime.Sub(procState.lastUpdateTime).Seconds()
				userDelta := currentUserSeconds - procState.lastUserSeconds
				sysDelta := currentSystemSeconds - procState.lastSysSeconds
				cpuDelta := userDelta + sysDelta // total CPU time during interval

				if wallDelta > 0 {
					// represents the average of cores utilized during the interval
					utilizationRatio := cpuDelta / wallDelta
					CPUUtilization.Set(utilizationRatio)
				}
			}

			procState.lastUserSeconds = currentUserSeconds
			procState.lastSysSeconds = currentSystemSeconds
			procState.lastUpdateTime = currentTime
		}
	}
	return nil
}

func updateCounter[T int | uint | float32 | float64](new T, old T, counter prometheus.Counter) T {
	incBy := float64(new - old)
	if incBy < 0 {
		// If the new value is less than the old value, it is likely that the service has been restarted.
		// In this case, we should report the new value as the increment.
		incBy = float64(new)
	}
	if incBy > 0 {
		counter.Add(incBy)
	}
	return new
}

// updateCounterWithUnified updates both the XRootD-specific counter and the unified storage counter
func updateCounterWithUnified[T int | uint | float32 | float64](new T, old T, counter prometheus.Counter, unifiedCounter *prometheus.CounterVec) T {
	incBy := float64(new - old)
	if incBy < 0 {
		incBy = float64(new)
	}
	if incBy > 0 {
		counter.Add(incBy)
		unifiedCounter.WithLabelValues(BackendXRootD).Add(incBy)
	}
	return new
}

// updateHistogramWithUnified updates both the XRootD-specific histogram and the unified storage histogram
func updateHistogramWithUnified(newTotalTime, oldTotalTime float64, newCount, oldCount int, histogram prometheus.Histogram, unifiedHistogram *prometheus.HistogramVec) {
	deltaTime := newTotalTime - oldTotalTime
	deltaCount := newCount - oldCount
	if deltaCount > 0 {
		avgLatency := deltaTime / float64(deltaCount)
		// Update both histograms for each operation that occurred
		for i := 0; i < deltaCount; i++ {
			histogram.Observe(avgLatency)
			unifiedHistogram.WithLabelValues(BackendXRootD).Observe(avgLatency)
		}
	}
}

// handleS3CacheStats processes the S3 cache stats
// It expects the blobs to be in JSON format and will update the metrics accordingly
// It returns an error if the blobs are empty or if there is an error in unmarshalling
// the JSON data
// It also handles the case where the total IO or wait time is less than the previous value
// by resetting the increment to 0.
// The s3file_stats event schema is as follows:
//
//	{
//	  "event": "s3file_stats",
//	  "hit_b": uint,
//	  "miss_b": uint,
//	  "full_hit": uint,
//	  "part_hit": uint,
//	  "miss": uint,
//	  "bypass_b": uint,
//	  "bypass": uint,
//	  "fetch_b": uint,
//	  "fetch": uint,
//	  "unused_b": uint,
//	  "prefetch_b": uint,
//	  "prefetch": uint,
//	  "errors": uint,
//	  "bypass_s": float,
//	  "fetch_s": float
//	}
func handleS3CacheStats(blobs [][]byte) error {

	// we need to process the blobs backwards to ensure that we are processing the last valid event
	// the most relevant data is the last valid event in the sequence of blobs
	for i := len(blobs) - 1; i >= 0; i-- {
		blob := blobs[i]
		s3fileStats := OssS3CacheGs{}
		if err := json.Unmarshal(blob, &s3fileStats); err != nil {
			log.Warningf("Failed to unmarshal S3 file stats json: %s", string(blob))
			continue
		}
		if !allowedEvents[s3fileStats.Event] {
			log.Warningf("handleS3CacheStats received an S3 file stats packet with an unrecognized event type (%s)", s3fileStats.Event)
			continue
		}
		lastS3CacheStats.HitB = updateCounter(s3fileStats.HitB, lastS3CacheStats.HitB, S3CacheBytes.WithLabelValues("hit"))
		lastS3CacheStats.MissB = updateCounter(s3fileStats.MissB, lastS3CacheStats.MissB, S3CacheBytes.WithLabelValues("miss"))
		lastS3CacheStats.BypassB = updateCounter(s3fileStats.BypassB, lastS3CacheStats.BypassB, S3CacheBytes.WithLabelValues("bypass"))
		lastS3CacheStats.FetchB = updateCounter(s3fileStats.FetchB, lastS3CacheStats.FetchB, S3CacheBytes.WithLabelValues("fetch"))
		lastS3CacheStats.UnusedB = updateCounter(s3fileStats.UnusedB, lastS3CacheStats.UnusedB, S3CacheBytes.WithLabelValues("unused"))
		lastS3CacheStats.PrefetchB = updateCounter(s3fileStats.PrefetchB, lastS3CacheStats.PrefetchB, S3CacheBytes.WithLabelValues("prefetch"))

		lastS3CacheStats.FullHit = updateCounter(s3fileStats.FullHit, lastS3CacheStats.FullHit, S3CacheHits.WithLabelValues("full"))
		lastS3CacheStats.PartHit = updateCounter(s3fileStats.PartHit, lastS3CacheStats.PartHit, S3CacheHits.WithLabelValues("partial"))
		lastS3CacheStats.Miss = updateCounter(s3fileStats.Miss, lastS3CacheStats.Miss, S3CacheHits.WithLabelValues("miss"))

		lastS3CacheStats.Bypass = updateCounter(s3fileStats.Bypass, lastS3CacheStats.Bypass, S3CacheRequests.WithLabelValues("bypass"))
		lastS3CacheStats.Fetch = updateCounter(s3fileStats.Fetch, lastS3CacheStats.Fetch, S3CacheRequests.WithLabelValues("fetch"))
		lastS3CacheStats.Prefetch = updateCounter(s3fileStats.Prefetch, lastS3CacheStats.Prefetch, S3CacheRequests.WithLabelValues("prefetch"))

		lastS3CacheStats.Errors = updateCounter(s3fileStats.Errors, lastS3CacheStats.Errors, S3CacheErrors)

		lastS3CacheStats.BypassS = updateCounter(s3fileStats.BypassS, lastS3CacheStats.BypassS, S3CacheRequestSeconds.WithLabelValues("bypass"))
		lastS3CacheStats.FetchS = updateCounter(s3fileStats.FetchS, lastS3CacheStats.FetchS, S3CacheRequestSeconds.WithLabelValues("fetch"))
		// Found and processed the last valid event, so we are done
		break
	}
	return nil
}

// handleOSSStats processes the OSS plugin stats
// It expects the blobs to be in JSON format and will update the metrics accordingly
// It returns an error if the blobs are empty or if there is an error in unmarshalling
// the JSON data
// It also handles the case where the total IO or wait time is less than the previous value
// by resetting the increment to 0.
// It also handles the case where the event is not in the allowed list by logging a debug message
// and continuing to the next blob.
//
// When processing multiple blobs, only the last valid OSS event (with event="oss_stats")
// in the list will be used to update the metrics. This means that if there are multiple
// valid OSS events in the list, only the last one's values will be recorded. Invalid events
// (wrong event type or malformed JSON) are ignored and do not affect the processing of
// subsequent events.
//
// The oss_stats event schema is as follows:
//
//	{
//		"event": "oss_stats",
//		"reads": 100,
//		"writes": 0,
//		"stats": 0,
//		"pgreads": 0,
//		"pgwrites": 0,
//		"readvs": 0,
//		"readv_segs": 0,
//		"dirlists": 0,
//		"dirlist_ents": 0,
//		"truncates": 0,
//		"unlinks": 0,
//		"chmods": 0,
//		"opens": 0,
//		"renames": 0,
//		"slow_reads": 0,
//		"slow_writes": 0,
//		"slow_stats": 0,
//		"slow_pgreads": 0,
//		"slow_pgwrites": 0,
//		"slow_readvs": 0,
//		"slow_readv_segs": 0,
//		"slow_dirlists": 0,
//		"slow_dirlist_ents": 0,
//		"slow_truncates": 0,
//		"slow_unlinks": 0,
//		"slow_chmods": 0,
//		"slow_opens": 0,
//		"slow_renames": 0,
//		"open_t": 0.0000,
//		"read_t": 0.0000,
//		"readv_t": 0.0000,
//		"pgread_t": 0.0000,
//		"pgwrite_t": 0.0000,
//		"dirlist_t": 0.0000,
//		"stat_t": 0.0000,
//		"truncate_t": 0.0000,
//		"unlink_t": 0.0000,
//		"rename_t": 0.0000,
//		"chmod_t": 0.0000,
//		"slow_open_t": 0.0000,
//		"slow_read_t": 0.0000,
//		"slow_readv_t": 0.0000,
//		"slow_pgread_t": 0.0000,
//		"slow_pgwrite_t": 0.0000,
//		"slow_dirlist_t": 0.0000,
//		"slow_stat_t": 0.0000,
//		"slow_truncate_t": 0.0000,
//		"slow_unlink_t": 0.0000,
//		"slow_rename_t": 0.0000,
//		"slow_chmod_t": 0.0000
//	}
//
// The event field is used to determine if the blob is a valid OSS event.
// The other fields are used to update the metrics accordingly.
// The slow_ prefix fields are used to update the slow operation histograms.
// The other fields are used to update the counters.
func handleOSSStats(blobs [][]byte) error {
	// updateHistogram updates the histogram with the average latency per operation for the given delta.
	// newTotalTime and oldTotalTime are the cumulative times (in seconds).
	// newCount and oldCount are the cumulative counts.
	// histogram is the Prometheus histogram to update.
	updateHistogram := func(newTotalTime, oldTotalTime float64, newCount, oldCount int, histogram prometheus.Histogram) {
		deltaTime := newTotalTime - oldTotalTime
		deltaCount := newCount - oldCount
		if deltaCount > 0 {
			avgLatency := deltaTime / float64(deltaCount)
			// Update the histogram for each operation that occurred.
			for i := 0; i < deltaCount; i++ {
				histogram.Observe(avgLatency)
			}

		}
	}
	// we need to process the blobs backwards to ensure that we are processing the last valid event
	// the most relevant data is the last valid event in the sequence of blobs
	for i := len(blobs) - 1; i >= 0; i-- {
		blob := blobs[i]
		ossStats := OSSStatsGs{}
		if err := json.Unmarshal(blob, &ossStats); err != nil {
			log.Debugf("Failed to unmarshal S3 file stats json: %s", string(blob))
			continue
		}
		if !allowedEvents[ossStats.Event] {
			log.Warningf("handleOSSStats received an OSS packet with an unrecognized event type (%s)", ossStats.Event)
			continue
		}
		// Update histograms (both XRootD-specific and unified metrics)
		updateHistogramWithUnified(ossStats.ReadT, lastOssStats.ReadT, ossStats.Reads, lastOssStats.Reads, OssReadTime, StorageReadTime)
		lastOssStats.ReadT = ossStats.ReadT
		updateHistogramWithUnified(ossStats.WriteT, lastOssStats.WriteT, ossStats.Writes, lastOssStats.Writes, OssWriteTime, StorageWriteTime)
		lastOssStats.WriteT = ossStats.WriteT
		updateHistogramWithUnified(ossStats.StatT, lastOssStats.StatT, ossStats.Stats, lastOssStats.Stats, OssStatTime, StorageStatTime)
		lastOssStats.StatT = ossStats.StatT
		updateHistogram(ossStats.PgreadT, lastOssStats.PgreadT, ossStats.Pgreads, lastOssStats.Pgreads, OssPgReadTime)
		lastOssStats.PgreadT = ossStats.PgreadT
		updateHistogram(ossStats.PgwriteT, lastOssStats.PgwriteT, ossStats.Pgwrites, lastOssStats.Pgwrites, OssPgWriteTime)
		lastOssStats.PgwriteT = ossStats.PgwriteT
		updateHistogram(ossStats.ReadvT, lastOssStats.ReadvT, ossStats.Readvs, lastOssStats.Readvs, OssReadvTime)
		lastOssStats.ReadvT = ossStats.ReadvT
		updateHistogramWithUnified(ossStats.DirlistT, lastOssStats.DirlistT, ossStats.Dirlists, lastOssStats.Dirlists, OssDirlistTime, StorageReaddirTime)
		lastOssStats.DirlistT = ossStats.DirlistT
		updateHistogramWithUnified(ossStats.TruncateT, lastOssStats.TruncateT, ossStats.Truncates, lastOssStats.Truncates, OssTruncateTime, StorageTruncateTime)
		lastOssStats.TruncateT = ossStats.TruncateT
		updateHistogramWithUnified(ossStats.UnlinkT, lastOssStats.UnlinkT, ossStats.Unlinks, lastOssStats.Unlinks, OssUnlinkTime, StorageUnlinkTime)
		lastOssStats.UnlinkT = ossStats.UnlinkT
		updateHistogramWithUnified(ossStats.ChmodT, lastOssStats.ChmodT, ossStats.Chmods, lastOssStats.Chmods, OssChmodTime, StorageChmodTime)
		lastOssStats.ChmodT = ossStats.ChmodT
		updateHistogramWithUnified(ossStats.OpenT, lastOssStats.OpenT, ossStats.Opens, lastOssStats.Opens, OssOpenTime, StorageOpenTime)
		lastOssStats.OpenT = ossStats.OpenT
		updateHistogramWithUnified(ossStats.RenameT, lastOssStats.RenameT, ossStats.Renames, lastOssStats.Renames, OssRenameTime, StorageRenameTime)
		lastOssStats.RenameT = ossStats.RenameT

		updateHistogramWithUnified(ossStats.SlowReadT, lastOssStats.SlowReadT, ossStats.SlowReads, lastOssStats.SlowReads, OssSlowReadTime, StorageSlowReadTime)
		lastOssStats.SlowReadT = ossStats.SlowReadT
		updateHistogramWithUnified(ossStats.SlowWriteT, lastOssStats.SlowWriteT, ossStats.SlowWrites, lastOssStats.SlowWrites, OssSlowWriteTime, StorageSlowWriteTime)
		lastOssStats.SlowWriteT = ossStats.SlowWriteT
		updateHistogramWithUnified(ossStats.SlowStatT, lastOssStats.SlowStatT, ossStats.SlowStats, lastOssStats.SlowStats, OssSlowStatTime, StorageSlowStatTime)
		lastOssStats.SlowStatT = ossStats.SlowStatT
		updateHistogram(ossStats.SlowPgreadT, lastOssStats.SlowPgreadT, ossStats.SlowPgreads, lastOssStats.SlowPgreads, OssSlowPgReadTime)
		lastOssStats.SlowPgreadT = ossStats.SlowPgreadT
		updateHistogram(ossStats.SlowPgwriteT, lastOssStats.SlowPgwriteT, ossStats.SlowPgwrites, lastOssStats.SlowPgwrites, OssSlowPgWriteTime)
		lastOssStats.SlowPgwriteT = ossStats.SlowPgwriteT
		updateHistogram(ossStats.SlowReadvT, lastOssStats.SlowReadvT, ossStats.SlowReadvs, lastOssStats.SlowReadvs, OssSlowReadvTime)
		lastOssStats.SlowReadvT = ossStats.SlowReadvT
		updateHistogramWithUnified(ossStats.SlowDirlistT, lastOssStats.SlowDirlistT, ossStats.SlowDirlists, lastOssStats.SlowDirlists, OssSlowDirlistTime, StorageSlowReaddirTime)
		lastOssStats.SlowDirlistT = ossStats.SlowDirlistT
		updateHistogramWithUnified(ossStats.SlowTruncateT, lastOssStats.SlowTruncateT, ossStats.SlowTruncates, lastOssStats.SlowTruncates, OssSlowTruncateTime, StorageSlowTruncateTime)
		lastOssStats.SlowTruncateT = ossStats.SlowTruncateT
		updateHistogramWithUnified(ossStats.SlowUnlinkT, lastOssStats.SlowUnlinkT, ossStats.SlowUnlinks, lastOssStats.SlowUnlinks, OssSlowUnlinkTime, StorageSlowUnlinkTime)
		lastOssStats.SlowUnlinkT = ossStats.SlowUnlinkT
		updateHistogramWithUnified(ossStats.SlowChmodT, lastOssStats.SlowChmodT, ossStats.SlowChmods, lastOssStats.SlowChmods, OssSlowChmodTime, StorageSlowChmodTime)
		lastOssStats.SlowChmodT = ossStats.SlowChmodT
		updateHistogramWithUnified(ossStats.SlowOpenT, lastOssStats.SlowOpenT, ossStats.SlowOpens, lastOssStats.SlowOpens, OssSlowOpenTime, StorageSlowOpenTime)
		lastOssStats.SlowOpenT = ossStats.SlowOpenT
		updateHistogramWithUnified(ossStats.SlowRenameT, lastOssStats.SlowRenameT, ossStats.SlowRenames, lastOssStats.SlowRenames, OssSlowRenameTime, StorageSlowRenameTime)
		lastOssStats.SlowRenameT = ossStats.SlowRenameT

		lastOssStats.Reads = updateCounterWithUnified(ossStats.Reads, lastOssStats.Reads, OssReadsCounter, StorageReadsTotal)
		lastOssStats.Writes = updateCounterWithUnified(ossStats.Writes, lastOssStats.Writes, OssWritesCounter, StorageWritesTotal)
		lastOssStats.Stats = updateCounterWithUnified(ossStats.Stats, lastOssStats.Stats, OssStatsCounter, StorageStatsTotal)
		lastOssStats.Pgreads = updateCounter(ossStats.Pgreads, lastOssStats.Pgreads, OssPgReadsCounter)
		lastOssStats.Pgwrites = updateCounter(ossStats.Pgwrites, lastOssStats.Pgwrites, OssPgWritesCounter)
		lastOssStats.Readvs = updateCounter(ossStats.Readvs, lastOssStats.Readvs, OssReadvCounter)
		lastOssStats.ReadvSegs = updateCounter(ossStats.ReadvSegs, lastOssStats.ReadvSegs, OssReadvSegsCounter)
		lastOssStats.Dirlists = updateCounterWithUnified(ossStats.Dirlists, lastOssStats.Dirlists, OssDirlistCounter, StorageReaddirTotal)
		lastOssStats.DirlistEnts = updateCounter(ossStats.DirlistEnts, lastOssStats.DirlistEnts, OssDirlistEntsCounter)
		lastOssStats.Truncates = updateCounterWithUnified(ossStats.Truncates, lastOssStats.Truncates, OssTruncateCounter, StorageTruncatesTotal)
		lastOssStats.Unlinks = updateCounterWithUnified(ossStats.Unlinks, lastOssStats.Unlinks, OssUnlinkCounter, StorageUnlinksTotal)
		lastOssStats.Chmods = updateCounterWithUnified(ossStats.Chmods, lastOssStats.Chmods, OssChmodCounter, StorageChmodsTotal)
		lastOssStats.Opens = updateCounterWithUnified(ossStats.Opens, lastOssStats.Opens, OssOpensCounter, StorageOpensTotal)
		lastOssStats.Renames = updateCounterWithUnified(ossStats.Renames, lastOssStats.Renames, OssRenamesCounter, StorageRenamesTotal)

		lastOssStats.SlowReads = updateCounterWithUnified(ossStats.SlowReads, lastOssStats.SlowReads, OssSlowReadsCounter, StorageSlowReadsTotal)
		lastOssStats.SlowWrites = updateCounterWithUnified(ossStats.SlowWrites, lastOssStats.SlowWrites, OssSlowWritesCounter, StorageSlowWritesTotal)
		lastOssStats.SlowStats = updateCounterWithUnified(ossStats.SlowStats, lastOssStats.SlowStats, OssSlowStatsCounter, StorageSlowStatsTotal)
		lastOssStats.SlowPgreads = updateCounter(ossStats.SlowPgreads, lastOssStats.SlowPgreads, OssSlowPgReadsCounter)
		lastOssStats.SlowPgwrites = updateCounter(ossStats.SlowPgwrites, lastOssStats.SlowPgwrites, OssSlowPgWritesCounter)
		lastOssStats.SlowReadvs = updateCounter(ossStats.SlowReadvs, lastOssStats.SlowReadvs, OssSlowReadvCounter)
		lastOssStats.SlowReadvSegs = updateCounter(ossStats.SlowReadvSegs, lastOssStats.SlowReadvSegs, OssSlowReadvSegsCounter)
		lastOssStats.SlowDirlists = updateCounterWithUnified(ossStats.SlowDirlists, lastOssStats.SlowDirlists, OssSlowDirlistCounter, StorageSlowReaddirTotal)
		lastOssStats.SlowDirlistEnts = updateCounter(ossStats.SlowDirlistEnts, lastOssStats.SlowDirlistEnts, OssSlowDirlistEntsCounter)
		lastOssStats.SlowTruncates = updateCounterWithUnified(ossStats.SlowTruncates, lastOssStats.SlowTruncates, OssSlowTruncateCounter, StorageSlowTruncatesTotal)
		lastOssStats.SlowUnlinks = updateCounterWithUnified(ossStats.SlowUnlinks, lastOssStats.SlowUnlinks, OssSlowUnlinkCounter, StorageSlowUnlinksTotal)
		lastOssStats.SlowChmods = updateCounterWithUnified(ossStats.SlowChmods, lastOssStats.SlowChmods, OssSlowChmodCounter, StorageSlowChmodsTotal)
		lastOssStats.SlowOpens = updateCounterWithUnified(ossStats.SlowOpens, lastOssStats.SlowOpens, OssSlowOpensCounter, StorageSlowOpensTotal)
		lastOssStats.SlowRenames = updateCounterWithUnified(ossStats.SlowRenames, lastOssStats.SlowRenames, OssSlowRenamesCounter, StorageSlowRenamesTotal)
		// Found and processed the last valid event, so we are done
		break
	}

	return nil
}

// handlesOSSPacket handles the OSS g-stream packets
// It expects the blobs to be in JSON format
// The blobs can be of different event types and come intermixed
// When grouping we preserve the order of the blobs in the original packet
// We will dispatch the blobs to the appropriate handler based on the event type
func handleOSSPacket(blobs [][]byte) error {
	if len(blobs) == 0 {
		return errors.New("no blobs in the OSS g-stream packet")
	}

	// This map will map the event type to the list of blobs that have that event type
	groupedEvents := make(map[string][][]byte)
	for _, blob := range blobs {
		ossEvent := OssGStreamEvent{}
		if err := json.Unmarshal(blob, &ossEvent); err != nil {
			return errors.Wrap(err, "failed to parse OSS event json")
		}
		if !allowedEvents[ossEvent.Event] {
			log.Warningf("handleOSSPacket received an OSS packet with an unrecognized event type (%s)", ossEvent.Event)
			continue
		}
		groupedEvents[ossEvent.Event] = append(groupedEvents[ossEvent.Event], blob)
	}

	for eventType, eventBlobs := range groupedEvents {
		switch eventType {
		case OssStatsEvent:
			if err := handleOSSStats(eventBlobs); err != nil {
				return errors.Wrap(err, "failed to handle OSS stats")
			}
		case S3FileStatsEvent:
			if err := handleS3CacheStats(eventBlobs); err != nil {
				return errors.Wrap(err, "failed to handle S3 file stats")
			}
		}
	}

	return nil
}

// handleThrottlePacket processes the throttle plugin stats
// It expects the blobs to be in JSON format and will update the metrics accordingly
// It also handles the case where the total IO or wait time is less than the previous value
// by resetting the increment to 0
// It returns an error if the blobs are empty or if there is an error in unmarshalling
// the JSON data
// It expects that the JSON data is in the format:
//
//	{
//	  "io_wait": 0.12345,
//	  "io_active": 67890,
//	  "io_total": 1
//	}
func handleThrottlePacket(blobs [][]byte) error {
	if len(blobs) == 0 {
		return errors.New("no blobs in the throttle packet")
	}

	for _, blob := range blobs {
		throttleGS := ThrottleGS{}
		if err := json.Unmarshal(blob, &throttleGS); err != nil {
			return errors.Wrap(err, "failed to parse throttle plugin stat json")
		}
		totalIOInc := 0
		if totalIOInc = throttleGS.IOTotal - lastTotalIO; totalIOInc < 0 {
			totalIOInc = 0
		}
		lastTotalIO = throttleGS.IOTotal

		waitTimeInc := 0.0
		if waitTimeInc = throttleGS.IOWaitTime - lastWaitTime; waitTimeInc < 0 {
			waitTimeInc = 0
		}
		lastWaitTime = throttleGS.IOWaitTime

		ServerTotalIO.Add(float64(totalIOInc))
		ServerActiveIO.Set(float64(throttleGS.IOActive))
		ServerIOWaitTime.Add(waitTimeInc)
	}
	return nil
}

// When XRootD v6 is released, these stats will be available over the g-stream
// Until then the stats are consumed from Cache.ClientStatisticsLocation
// This function should be called with the contents of the file / udp packet
func handleXrdcurlstatsPacket(stats []byte) error {
	var xrdCurlStats XrdCurlStats
	if err := json.Unmarshal(stats, &xrdCurlStats); err != nil {
		return errors.Wrap(err, "failed to unmarshal xrdcurlstats packet")
	}

	log.Tracef("XrdCurlStats: %v (raw: %s)", xrdCurlStats, string(stats))

	// File prefetch stats
	lastXrdCurlStats.File.Prefetch.Count = updateCounter(xrdCurlStats.File.Prefetch.Count, lastXrdCurlStats.File.Prefetch.Count, XrdclFilePrefetchCount)
	lastXrdCurlStats.File.Prefetch.Expired = updateCounter(xrdCurlStats.File.Prefetch.Expired, lastXrdCurlStats.File.Prefetch.Expired, XrdclFilePrefetchExpired)
	lastXrdCurlStats.File.Prefetch.Failed = updateCounter(xrdCurlStats.File.Prefetch.Failed, lastXrdCurlStats.File.Prefetch.Failed, XrdclFilePrefetchFailed)
	lastXrdCurlStats.File.Prefetch.ReadsHit = updateCounter(xrdCurlStats.File.Prefetch.ReadsHit, lastXrdCurlStats.File.Prefetch.ReadsHit, XrdclFilePrefetchReadsHit)
	lastXrdCurlStats.File.Prefetch.ReadsMiss = updateCounter(xrdCurlStats.File.Prefetch.ReadsMiss, lastXrdCurlStats.File.Prefetch.ReadsMiss, XrdclFilePrefetchReadsMiss)
	lastXrdCurlStats.File.Prefetch.BytesUsed = updateCounter(xrdCurlStats.File.Prefetch.BytesUsed, lastXrdCurlStats.File.Prefetch.BytesUsed, XrdclFilePrefetchBytesUsed)

	// Queue stats
	lastXrdCurlStats.Queues.Produced = updateCounter(xrdCurlStats.Queues.Produced, lastXrdCurlStats.Queues.Produced, XrdclQueueProduced)
	lastXrdCurlStats.Queues.Consumed = updateCounter(xrdCurlStats.Queues.Consumed, lastXrdCurlStats.Queues.Consumed, XrdclQueueConsumed)
	XrdclQueuePending.Set(xrdCurlStats.Queues.Pending)
	lastXrdCurlStats.Queues.Rejected = updateCounter(xrdCurlStats.Queues.Rejected, lastXrdCurlStats.Queues.Rejected, XrdclQueueRejected)

	// Worker stats
	var workers map[string]float64
	if err := json.Unmarshal(xrdCurlStats.Workers, &workers); err != nil {
		return errors.Wrap(err, "failed to unmarshal xrdcurlstats workers")
	}

	if lastXrdCurlStats.Workers == nil {
		lastXrdCurlStats.Workers = make(map[string]float64)
	}

	for key, value := range workers {
		if key == "oldest_op" {
			XrdclWorkerOldestOp.Set(value)
			continue
		}
		if key == "oldest_cycle" {
			XrdclWorkerOldestCycle.Set(value)
			continue
		}

		// Update counters using deltas
		oldValue := lastXrdCurlStats.Workers[key]
		incBy := value - oldValue
		if incBy < 0 {
			incBy = value
		}
		lastXrdCurlStats.Workers[key] = value

		if incBy <= 0 {
			continue
		}

		if strings.HasPrefix(key, "http_") {
			parts := strings.SplitN(key, "_", 4)
			if len(parts) == 3 { // http_VERB_field
				verb, field := parts[1], parts[2]
				switch field {
				case "started":
					XrdclHTTPRequests.WithLabelValues(verb, "", "started").Add(incBy)
				case "error":
					XrdclHTTPRequests.WithLabelValues(verb, "", "error").Add(incBy)
				case "timeout":
					XrdclHTTPRequests.WithLabelValues(verb, "", "timeout").Add(incBy)
				case "preheaderduration":
					XrdclHTTPRequestDuration.WithLabelValues(verb, "", "preheader").Add(incBy)
				}
			} else if len(parts) == 4 { // http_VERB_STATUS_field
				verb, status, field := parts[1], parts[2], parts[3]
				switch field {
				case "duration":
					XrdclHTTPRequestDuration.WithLabelValues(verb, status, "duration").Add(incBy)
				case "pauseduration":
					XrdclHTTPRequestDuration.WithLabelValues(verb, status, "pause_duration").Add(incBy)
				case "bytes":
					XrdclHTTPBytes.WithLabelValues(verb, status).Add(incBy)
				case "finished":
					XrdclHTTPRequests.WithLabelValues(verb, status, "finished").Add(incBy)
				case "servertimeout":
					XrdclHTTPRequests.WithLabelValues(verb, status, "server_timeout").Add(incBy)
				case "clienttimeout":
					XrdclHTTPRequests.WithLabelValues(verb, status, "client_timeout").Add(incBy)
				}
			}
		} else if strings.HasPrefix(key, "conncall_") {
			parts := strings.Split(key, "_")
			if len(parts) == 2 {
				fieldType := parts[1]
				switch fieldType {
				case "error", "started", "success", "timeout":
					XrdclConncall.WithLabelValues(fieldType).Add(incBy)
				}
			}
		}
	}

	return nil
}
