package origin_ui

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/pelicanplatform/pelican/director"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func PeriodicAdvertiseOrigin() error {
	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		err := AdvertiseOrigin()
		if err != nil {
			log.Warningln("Origin advertise failed:", err)
		}
		for {
			<-ticker.C
			err := AdvertiseOrigin()
			if err != nil {
				log.Warningln("Origin advertise failed:", err)
			}
		}
	}()

	return nil
}

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
	if viper.GetBool("TLSSkipVerify") {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client = http.Client{Transport: tr}
	}
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
