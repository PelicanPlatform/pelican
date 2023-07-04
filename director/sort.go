package director

import "net/netip"

// TODO: Actually invoke GeoIP sorting
func SortCaches(_ netip.Addr, ads []ServerAd) ([]ServerAd, error) {
	return ads, nil
}
