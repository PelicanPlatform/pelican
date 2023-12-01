package param

import (
	"errors"
	"sync"

	"github.com/spf13/viper"
)

var (
	viperConfig *config
	configMutex sync.RWMutex
)

// Unmarshal Viper config into a struct viperConfig and returns it
func UnmarshalConfig() (*config, error) {
	configMutex.Lock()
	defer configMutex.Unlock()
	viperConfig = new(config)
	err := viper.Unmarshal(viperConfig)
	if err != nil {
		return nil, err
	}

	return viperConfig, nil
}

// Return the unmarshaled viper config struct as a pointer
func GetUnmarshaledConfig() (*config, error) {
	configMutex.RLock()
	defer configMutex.RUnlock()
	if viperConfig == nil {
		return nil, errors.New("Config hasn't been unmarshaled yet.")
	}
	return viperConfig, nil
}
