package config

import (
	"net"
	"net/url"
	"strconv"

	"github.com/pelicanplatform/pelican/param"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func UpdateConfigFromListener(ln net.Listener) {
	// If we allow net.Listen to select a random open port, we should update the
	// configuration with its value.
	if param.Server_WebPort.GetInt() == 0 {
		addr := ln.Addr()
		tcpAddr, ok := addr.(*net.TCPAddr)
		if ok {
			viper.Set("Server.WebPort", tcpAddr.Port)
			serverUrlStr := param.Server_ExternalWebUrl.GetString()
			serverUrl, err := url.Parse(serverUrlStr)
			if err == nil {
				viper.Set("Server.WebHost", serverUrl.Hostname())
				viper.Set("Server.ExternalWebUrl", "https://"+serverUrl.Hostname()+":"+strconv.Itoa(tcpAddr.Port))
				log.Debugln("Random web port used; updated external web URL to", param.Server_ExternalWebUrl.GetString())
			} else {
				log.Errorln("Unable to update external web URL for random port; unable to parse existing URL:", serverUrlStr)
			}
		} else {
			log.Error("Unable to determine TCP address of runtime engine")
		}
	}
}
