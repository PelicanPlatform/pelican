package pelican

import (
	"net"

	"github.com/gin-gonic/gin"
        "github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
        log "github.com/sirupsen/logrus"
        "github.com/spf13/viper"
	"github.com/zsais/go-gin-prometheus"

)

var (
	PacketsReceived = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xrootd_monitoring_packets_received",
		Help: "The total number of monitoring UDP packets received",
	})
)

func ConfigureMonitoring() (int, error) {
	lower := viper.GetInt("MonitoringPortLower")
	higher := viper.GetInt("MonitoringPortHigher")

	addr := net.UDPAddr{IP: net.ParseIP("127.0.0.1")}
	var conn *net.UDPConn
	var err error
	for portAttempt := lower; portAttempt < higher; portAttempt++ {
		addr.Port = portAttempt
		conn, err = net.ListenUDP("udp", &addr)
		if err == nil {
			break
		}
	}
	if conn == nil {
		if err != nil {
			return -1, err
		}
		return -1, errors.New("Failed to create a UDP listening socket for monitoring")
	}

	// Set the read buffer size to 1 MB
	err = conn.SetReadBuffer(1024 * 1024)
	if err != nil {
		return -1, err
	}

	go func() {
		var buf [65536]byte
		for {
			// TODO: actually parse the UDP packets
			_, _, err := conn.ReadFromUDP(buf[:])
			if err != nil {
				log.Errorln("Failed to read from UDP connection", err)
				continue
			}
			PacketsReceived.Inc()
		}
	}()

	return addr.Port, nil
}

func ConfigureMetrics(engine *gin.Engine) error {
	prometheusMonitor := ginprometheus.NewPrometheus("gin")
	prometheusMonitor.Use(engine)
	/*handler := promhttp.Handler()
	engine.GET("/metrics", func(context *gin.Context) {
		handler.ServeHTTP(context.Writer, context.Request)
	})*/
	return nil
}
