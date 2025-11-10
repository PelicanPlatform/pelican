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

	PelicanBrokerConnections = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_broker_connections_total",
		Help: "The number of connections made to the service via a connection broker.",
	}, []string{"server_type"})

	PelicanBrokerApiRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_broker_api_requests_total",
		Help: "The number of API requests made to the service via a connection broker.",
	}, []string{"server_type"})

	PelicanBrokerObjectRequests = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pelican_broker_object_requests_total",
		Help: "The number of object requests made to the service via a connection broker.",
	})
)
