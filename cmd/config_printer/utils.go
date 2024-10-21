package config_printer

import (
	"fmt"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/spf13/viper"
)

func InitServerClientConfig(v *viper.Viper) *param.Config {
	config.SetServerDefaults(v)
	config.SetClientDefaults(v)

	exapandedConfig, err := param.NonGlobalUnmarshalConfig(v)
	if err != nil {
		fmt.Println("Error:", err)
	}
	return exapandedConfig

}
