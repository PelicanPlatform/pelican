//go:build windows

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

package launchers

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

func OriginServe(ctx context.Context, engine *gin.Engine, egrp *errgroup.Group, modules server_structs.ServerType) (server_structs.XRootDServer, error) {
	return nil, errors.New("Origin module is not supported on Windows")
}

func OriginServeFinish(ctx context.Context, egrp *errgroup.Group) error {
	return errors.New("Origin module is not supported on Windows")
}
