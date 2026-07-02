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

package origin

import (
	"github.com/gin-gonic/gin"

	"github.com/pelicanplatform/pelican/web_ui"
)

func RegisterOriginWebAPI(routerGroup *gin.RouterGroup) error {

	routerGroup.GET("/exports", web_ui.AuthHandler, web_ui.AdminAuthHandler, handleExports)
	// Public-info slice of /exports: just the FederationPrefix list,
	// no storage/S3/Globus details, no editUrl tokens. Reachable by
	// any authenticated caller — the prefixes themselves are
	// advertised to the registry, so listing them leaks nothing the
	// federation can't already see. Drives the collection-onboarding
	// form's prefix dropdown so a collection-admin (who isn't a
	// system admin) can still pick an exported prefix.
	routerGroup.GET("/exports/prefixes", web_ui.AuthHandler, handleExportPrefixes)

	collectionAPIGroup := routerGroup.Group("/collections") // Path is /api/v1.0/origin_ui/collections
	RegisterCollectionsAPI(collectionAPIGroup)

	globusAPIGroup := routerGroup.Group("/globus") // Path is /api/v1.0/origin_ui/globus
	if err := RegisterGlobusAPI(globusAPIGroup); err != nil {
		return err
	}

	return nil
}
