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

package director

import (
	"context"
	"testing"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_structs"
)

// initServerForTest wraps config.InitServer and restores the previous log level
// after the test to avoid leaking debug logging into subsequent tests.
func initServerForTest(t *testing.T, ctx context.Context, serverType server_structs.ServerType) error {
	t.Helper()

	originLevel := config.GetEffectiveLogLevel()
	err := config.InitServer(ctx, serverType)
	t.Cleanup(func() {
		config.SetLogging(originLevel)
	})

	return err
}
