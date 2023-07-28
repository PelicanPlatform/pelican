package origin_ui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/pelicanplatform/pelican/director"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

func AdvertiseOrigin() error {
	name := viper.GetString("Sitename")
	if name == "" {
		return errors.New("Origin name isn't set")
	}
	// TODO: waiting on a different branch to merge origin URL generation
	originUrl := "https://localhost:8444"

	ad := director.OriginAdvertise{
		Name: name,
		URL:  originUrl,
		Namespaces: make([]director.NamespaceAd, 0),
	}

	body, err := json.Marshal(ad)
	if err != nil {
		return errors.Wrap(err, "Failed to generate JSON description of origin")
	}

	directorUrlStr := viper.GetString("DirectorURL")
	if directorUrlStr == "" {
		return errors.New("Director endpoint URL is not known")
	}
	directorUrl, err := url.Parse(directorUrlStr)
	if err != nil {
		return errors.Wrap(err, "Failed to parse DirectorURL")
	}
	directorUrl.Path = "/api/v1.0/director/registerOrigin"

	req, err := http.NewRequest("POST", directorUrl.String(), bytes.NewBuffer(body))
	if err != nil {
		return errors.Wrap(err, "Failed to create POST request for director registration")
	}

	req.Header.Set("Content-Type", "application/json")

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "Failed to start request for director registration")
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		return fmt.Errorf("Error response %v from director registration: %v", resp.StatusCode, resp.Status)
	}

	return nil
}
