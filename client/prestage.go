/***************************************************************
 *
 * Copyright (C) 2024, Morgridge Institute for Research
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

package client

import (
	"context"
	"fmt"
	"runtime/debug"

	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// Single-shot call to prestage a single prefix
func DoPrestage(ctx context.Context, prefixUrl string, options ...TransferOption) (transferResults []TransferResults, err error) {
	// First, create a handler for any panics that occur
	defer func() {
		if r := recover(); r != nil {
			log.Debugln("Panic captured while attempting to perform prestage:", r)
			log.Debugln("Panic caused by the following", string(debug.Stack()))
			ret := fmt.Sprintf("Unrecoverable error (panic) captured in prestage: %v", r)
			err = errors.New(ret)
		}
	}()

	// Parse the source with URL parse
	pUrl, err := pelican_url.Parse(prefixUrl, []pelican_url.ParseOption{pelican_url.ValidateQueryParams(true), pelican_url.AllowUnknownQueryParams(true)}, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse source URL: %s", prefixUrl)
	}

	success := false

	te, err := NewTransferEngine(ctx)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err := te.Shutdown(); err != nil {
			log.Errorln("Failure when shutting down transfer engine:", err)
		}
	}()
	tc, err := te.NewClient(options...)
	if err != nil {
		return
	}
	tj, err := tc.NewPrestageJob(context.Background(), pUrl.GetRawUrl())
	if err != nil {
		return
	}
	err = tc.Submit(tj)
	if err != nil {
		return
	}

	transferResults, err = tc.Shutdown()
	if err == nil {
		if tj.lookupErr == nil {
			success = true
		} else {
			err = tj.lookupErr
		}
	}
	var downloaded int64 = 0
	for _, result := range transferResults {
		downloaded += result.TransferredBytes
		if err == nil && result.Error != nil {
			success = false
			err = result.Error
		}
	}

	if success {
		// Get the final size of the download file
	} else {
		log.Error("Prestage failed:", err)
	}

	if !success {
		// If there's only a single transfer error, remove the wrapping to provide
		// a simpler error message.  Results in:
		//    failed download from local-cache: server returned 404 Not Found
		// versus:
		//    failed to download file: transfer error: failed download from local-cache: server returned 404 Not Found
		var te *TransferErrors
		if errors.As(err, &te) {
			if len(te.Unwrap()) == 1 {
				var tae *TransferAttemptError
				if errors.As(te.Unwrap()[0], &tae) {
					return nil, tae
				} else {
					return nil, errors.Wrap(err, "failed to prestage file")
				}
			}
			return nil, te
		}
		return nil, errors.Wrap(err, "failed to prestage file")
	} else {
		return transferResults, err
	}
}
