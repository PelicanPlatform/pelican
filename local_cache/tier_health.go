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
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/metrics"
)

const (
	// tierProbeKey is the object the liveness probe writes and reads back.
	// Like the identity object it sits outside the aa/bb/hash layout, so the
	// consistency sweep never mistakes it for an orphan.
	tierProbeKey = ".pelican-health"
	// tierProbeSize is how much the probe writes: enough to exercise a real
	// upload and download without costing anything noticeable.
	tierProbeSize = 4096
	// tierProbeInterval is the gap between probes of each target.
	tierProbeInterval = time.Minute
	// tierProbeTimeout bounds one probe, write and read together.
	tierProbeTimeout = 30 * time.Second
	// tierProbeDegradedAfter is how many consecutive failed probes turn a
	// warning into a degraded status; one failure may be a blip.
	tierProbeDegradedAfter = 3
)

// probe writes a small object to the target and reads it back, recording
// whether the target is usable.  A target that fails is skipped by the
// uploader until a later probe succeeds; its objects are still served (a
// redirect does not touch the target at all) but may fail if it stays down.
func (t *tierTarget) probe(ctx context.Context) error {
	err := t.roundTrip(ctx)
	if err == nil {
		t.probeFailures.Store(0)
		t.healthy.Store(true)
		tierTargetUp.WithLabelValues(t.metricLabel()).Set(1)
		return nil
	}
	t.probeFailures.Add(1)
	t.healthy.Store(false)
	tierTargetUp.WithLabelValues(t.metricLabel()).Set(0)
	t.lastProbeError.Store(err.Error())
	return err
}

// roundTrip uploads random bytes to the probe key and checks they read back
// unchanged.
func (t *tierTarget) roundTrip(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, tierProbeTimeout)
	defer cancel()

	want := make([]byte, tierProbeSize)
	if _, err := rand.Read(want); err != nil {
		return errors.Wrap(err, "failed to generate probe data")
	}
	if _, err := t.backend.Put(ctx, tierProbeKey, "application/octet-stream", int64(len(want)), bytes.NewReader(want)); err != nil {
		return errors.Wrap(err, "write failed")
	}
	rc, err := t.backend.OpenRange(ctx, tierProbeKey, 0, nil)
	if err != nil {
		return errors.Wrap(err, "read failed")
	}
	defer rc.Close()
	got, err := io.ReadAll(io.LimitReader(rc, tierProbeSize+1))
	if err != nil {
		return errors.Wrap(err, "read failed")
	}
	if !bytes.Equal(got, want) {
		return errors.New("read back different bytes than were written")
	}
	return nil
}

// probeLoop probes every target periodically and publishes the result as the
// cache's tiering-storage health component.  It is the component's only
// writer.
func (u *tierUploader) probeLoop(ctx context.Context) {
	for {
		for _, target := range u.storage.tierTargets {
			if ctx.Err() != nil {
				return
			}
			_ = target.probe(ctx)
		}
		u.publishHealth()
		select {
		case <-ctx.Done():
			return
		case <-time.After(tierProbeInterval):
		}
	}
}

// publishHealth folds the targets' probe results into one health status:
// OK when every target answers, a warning when one has just started failing,
// and degraded once one has failed tierProbeDegradedAfter probes in a row.
func (u *tierUploader) publishHealth() {
	status := metrics.StatusOK
	var failing []string
	for _, target := range u.storage.tierTargets {
		failures := target.probeFailures.Load()
		if failures == 0 {
			continue
		}
		lastErr, _ := target.lastProbeError.Load().(string)
		failing = append(failing, fmt.Sprintf("%s (%d failed probe(s): %s)", target.DisplayURL(), failures, lastErr))
		if failures >= tierProbeDegradedAfter {
			status = metrics.StatusDegraded
		} else if status == metrics.StatusOK {
			status = metrics.StatusWarning
		}
	}
	message := fmt.Sprintf("%d tiering target(s) reachable", len(u.storage.tierTargets))
	if len(failing) > 0 {
		sort.Strings(failing)
		message = "Tiering targets not answering: " + strings.Join(failing, "; ")
	}
	metrics.SetComponentHealthStatus(metrics.Cache_TieringStorage, status, message)
}
