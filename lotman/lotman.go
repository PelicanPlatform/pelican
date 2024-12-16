//go:build !lotman || (lotman && linux && ppc64le) || !linux

// For now we're shutting off LotMan due to weirdness with purego. When we return to this, remember
// that purego doesn't support (linux && ppc64le), so we'll need to add that back here.
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

// LotMan is only supported on Linux at the moment. This file is a placeholder for other platforms and is
// intended to export any functions that might be called outside of the package
package lotman

import (
	"context"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/server_structs"
)

func RegisterLotman(ctx context.Context, router *gin.RouterGroup) {
	log.Warningln("LotMan is not supported on this platform. Skipping...")
}

func InitLotman(adsFromFed []server_structs.NamespaceAdV2) bool {
	log.Warningln("LotMan is not supported on this platform. Skipping...")
	return false
}
