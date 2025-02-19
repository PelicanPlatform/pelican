package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	PelicanServerXRootDLastCrash = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_server_xrootd_last_crash",
		Help: "The timestamp of the last crash of the XRootD server",
	}, []string{"server_type"})
)
