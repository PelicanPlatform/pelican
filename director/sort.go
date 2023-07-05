package director

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/oschwald/geoip2-golang"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	maxMindURL string = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=%s&suffix=tar.gz"
)

var (
	maxMindReader atomic.Pointer[geoip2.Reader]
)

type (
	SwapMap struct {
		Distance float64
		Index int
	}

	SwapMaps []SwapMap
)

func (me SwapMaps) Len() int {
	return len(me)
}

func (me SwapMaps) Less(left, right int) bool {
	return me[left].Distance < me[right].Distance
}

func (me SwapMaps) Swap(left, right int) {
	me[left], me[right] = me[right], me[left]
}

func GetLatLong(addr netip.Addr) (lat float64, long float64, err error) {
	ip := net.IP(addr.AsSlice())
	reader := maxMindReader.Load()
	if reader == nil {
		err = errors.New("No GeoIP database is available")
		return
	}
	record, err := reader.City(ip)
	if err != nil {
		return
	}
	lat = record.Location.Latitude
	long = record.Location.Longitude
	return
}


func SortCaches(addr netip.Addr, ads []ServerAd) ([]ServerAd, error) {
	distances := make(SwapMaps, len(ads))
	lat, long, err := GetLatLong(addr)
	isInvalid := err != nil
	for idx, ad := range ads {
		if isInvalid || (ad.Latitude == 0 && ad.Longitude == 0) {
			// Unable to compute distances for this server; just do random distances.
			// Note that valid distances are between 0 and 1, hence (1 + random) is always
			// going to be sorted after valid distances.
			distances[idx] = SwapMap{1 + rand.Float64(), idx}
		} else {
			distances[idx] = SwapMap{distanceOnSphere(lat, long, ad.Latitude, ad.Longitude),
				idx}
		}
	}
	sort.Sort(distances)
	resultAds := make([]ServerAd, len(ads))
	for idx, distance := range distances {
		resultAds[distance.Index] = ads[idx]
	}
	return resultAds, nil
}

func DownloadDB(localFile string) error {
	keyFile := viper.GetString("MaxMindKeyFile")
	if keyFile == "" {
		return errors.New("No MaxMind license key found in MaxMindKeyFile config parameter")
	}
	contents, err := os.ReadFile(keyFile)
	if err != nil {
		return err
	}
	licenseKey := strings.TrimSpace(string(contents))
	url := fmt.Sprintf(maxMindURL, licenseKey)
	localDir := filepath.Dir(localFile)
	fileHandle, err := os.CreateTemp(localDir, filepath.Base(localFile) + ".tmp")
	if err != nil {
		return err
	}
	defer fileHandle.Close()
	resp, err := http.Get(url)
	if err != nil {
		os.Remove(fileHandle.Name())
		return err
	}
	defer resp.Body.Close()

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	foundDB := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		baseName := path.Base(hdr.Name)
		if baseName != "GeoLite2-City.mmdb" {
			continue
		}
		if _, err = io.Copy(fileHandle, resp.Body); err != nil {
			os.Remove(fileHandle.Name())
			return err
		}
		foundDB = true
		break
	}
	if !foundDB {
		return errors.New("GeoIP database not found in downloaded resource")
	}
	if err = os.Rename(fileHandle.Name(), localFile); err != nil {
		return err
	}
	return nil
}

func PeriodicReload() {
	for {
		time.Sleep(time.Hour * 24)
		localFile := viper.GetString("GeoIPLocation")
		if err := DownloadDB(localFile); err != nil {
			log.Warningln("Failed to download GeoIP database:", err)
		} else {
			localReader, err := geoip2.Open(localFile)
			if err != nil {
				log.Warningln("Failed to re-open GeoIP database:", err)
			} else {
				maxMindReader.Store(localReader)
			}
		}
	}
}

func InitializeDB() {
	go PeriodicReload()
	localFile := viper.GetString("GeoIPLocation")
	localReader, err := geoip2.Open(localFile)
	if err != nil {
		log.Warningln("Local GeoIP database file not present; will attempt a download.", err)
		err = DownloadDB(localFile)
		if err != nil {
			log.Errorln("Failed to download GeoIP database!  Will not be available", err)
			return
		}
		localReader, err = geoip2.Open(localFile)
		if err != nil {
			log.Errorln("Failed to reopen GeoIP database!  Will not be available", err)
			return
		}
	}
	maxMindReader.Store(localReader)
}

func init() {
	InitializeDB()
}
