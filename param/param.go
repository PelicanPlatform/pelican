package param

import (
	"errors"

	"github.com/spf13/viper"
)

//go:generate go run ../generate/param_generator.go

var (
	viperConfig *config
)

// Unmarshal Viper config into a struct viperConfig
func UnmarshalConfig() error {
	viperConfig = new(config)
	err := viper.Unmarshal(viperConfig)
	if err != nil {
		return err
	}

	return nil
}

// Return the unmarshaled viper config struct as a pointer
func GetUnmarshaledConfig() (*config, error) {
	if viperConfig == nil {
		return nil, errors.New("Config hasn't been unmarshaled yet.")
	}
	return viperConfig, nil
}
