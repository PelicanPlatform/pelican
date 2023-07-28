package origin_ui

import (
	"errors"

	"github.com/pelicanplatform/pelican/director"
	"github.com/spf13/viper"
)

func AdvertiseOrigin() error {
	name := viper.GetString("Sitename")
	if name == "" {
		return errors.New("Origin name isn't set")
	}
	// TODO: waiting on a different branch to merge origin URL generation
	url := "https://localhost:8444"

	ad := director.OriginAdvertise{
		Name: name,
		URL:  url,
		Namespaces: make([]director.NamespaceAd, 0),
	}
	_ = ad
	return nil
}
