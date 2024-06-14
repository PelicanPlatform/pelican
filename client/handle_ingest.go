/***************************************************************
 *
 * Copyright (C) 2024, University of Nebraska-Lincoln
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
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

func version_status(filePath string) (string, uint64, error) {
	base := path.Base(filePath)
	dir := path.Dir(filePath)

	hash, localSize, err := unique_hash(filePath)
	if err != nil {
		return "", 0, err
	}
	return path.Join(dir, fmt.Sprintf("%s.%s", base, hash)), localSize, nil
}

func generateDestination(filePath string, originPrefix string, shadowOriginPrefix string) (string, uint64, error) {
	hashRaw, localSize, err := version_status(filePath)
	if err != nil {
		return "", 0, err
	}
	hashString := path.Clean(hashRaw)
	cleanedOriginPrefix := path.Clean(originPrefix)
	if strings.HasPrefix(hashString, cleanedOriginPrefix) {
		return shadowOriginPrefix + hashString[len(cleanedOriginPrefix):], localSize, nil
	}
	return "", 0, errors.New("File path must have the origin prefix")
}

func DoShadowIngest(ctx context.Context, sourceFile string, originPrefix string, shadowOriginPrefix string, options ...TransferOption) (int64, string, error) {
	// After each transfer attempt, we'll check to see if the local file was modified.  If so, we'll re-upload.
	for idx := 0; idx < 10; idx++ {
		shadowFile, localSize, err := generateDestination(sourceFile, originPrefix, shadowOriginPrefix)
		log.Debugln("Resulting shadow URL:", shadowFile)
		if err != nil {
			return 0, "", err
		}

		lastRemoteSize := uint64(0)
		lastUpdateTime := time.Now()
		startTime := lastUpdateTime
		maxRuntime := float64(localSize/10*1024*1024) + 300
		for {
			fileInfo, err := DoStat(ctx, shadowFile, options...)
			remoteSize := uint64(fileInfo.Size)
			if httpErr, ok := err.(*HttpErrResp); ok {
				if httpErr.Code == 404 {
					break
				} else {
					return 0, "", err
				}
			} else if err != nil {
				return 0, "", err
			}
			if localSize == remoteSize {
				return 0, shadowFile, err
			}
			log.Debugf("Remote file exists but it is incorrect size; actual size %v, expected %v.", remoteSize, localSize)

			// If the remote file size is growing, then wait a bit; perhaps someone
			// else is uploading the same file concurrently.
			if duration_s := time.Since(lastUpdateTime).Seconds(); duration_s > 10 {
				// Other uploader is too slow; let's do it ourselves
				if float64(remoteSize-lastRemoteSize)/duration_s < 1024*1024 {
					log.Warnln("Remote uploader is too slow; will do upload from this client")
					break
				}
				lastRemoteSize = remoteSize
				lastUpdateTime = time.Now()
			}
			// Out of an abundance of caution, never wait more than 10m.
			if time.Since(startTime).Seconds() > maxRuntime {
				log.Warnln("Remote uploader took too long to upload file; will do upload from this client")
				break
			}
			log.Debugf("Will sleep for 5 seconds to see if another client is currently uploading the file")
			// TODO: Could use a clever backoff scheme here.
			time.Sleep(5 * time.Second)
		}

		transferResults, err := DoCopy(ctx, sourceFile, shadowFile, false, options...)
		if err != nil {
			return 0, "", err
		}

		// See if the file was modified while we were uploading; if not, we'll return success
		shadowFilePost, _, err := generateDestination(sourceFile, originPrefix, shadowOriginPrefix)
		if err != nil {
			return 0, "", err
		}
		if shadowFilePost == shadowFile {
			return transferResults[0].TransferredBytes, shadowFile, err
		}
	}
	return 0, "", errors.New("After 10 upload attempts, file was still being modified during ingest.")
}
