//go:build !windows

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

package launchers

import (
	"context"
	_ "embed"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/p11proxy"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

func initPKCS11(ctx context.Context, egrp *errgroup.Group, modules server_structs.ServerType) {
	proxy, err := p11proxy.Start(ctx, p11proxy.Options{}, modules)
	if err != nil {
		log.Warnf("PKCS#11 helper failed to initialize: %v", err)
	} else if proxy != nil && proxy.Info().Enabled {
		info := proxy.Info()
		log.Infof("PKCS#11 helper enabled. For manual test, use OpenSSL in another shell:")
		log.Infof("  export P11_KIT_SERVER_ADDRESS=%s", info.ServerAddress)
		log.Infof("  export OPENSSL_CONF=%s", info.OpenSSLConfPath)
		log.Infof("  openssl s_server -accept 8500 -cert %s -key \"%s\" -engine pkcs11 -keyform engine -quiet", info.CertPath, info.PKCS11URL)
		log.Infof("And in another shell:")
		log.Infof("  openssl s_client -connect 127.0.0.1:8500 -servername localhost -CAfile %s", param.Server_TLSCACertificateFile.GetString())
		egrp.Go(func() error { <-ctx.Done(); return proxy.Stop() })
	} else {
		if param.Server_EnablePKCS11.GetBool() {
			log.Warnf("PKCS#11 helper auto-disabled. Install openssl, p11-kit, p11-kit-modules, libengine-pkcs11-openssl to enable; or set %s=false to suppress this message.", param.Server_EnablePKCS11.GetName())
		}
	}
}
