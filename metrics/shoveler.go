/***************************************************************
 *
 * 	Copyright 2021 Derek Weitzel
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ***************************************************************/

package metrics

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	shoveler "github.com/opensciencegrid/xrootd-monitoring-shoveler"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/param"
)

type ipMappingItem struct {
	All    string `mapstructure:"All"`
	Source string `mapstructure:"Source"`
	Dest   string `mapstructure:"Dest"`
}

var (
	mapAll         string
	ipMap          map[string]string
	shovelerLogger log.FieldLogger
)

func configShoveler(c *shoveler.Config) error {
	c.MQ = param.Shoveler_MessageQueueProtocol.GetString()
	if c.MQ != "amqp" && c.MQ != "stomp" {
		return fmt.Errorf("Bad config for Shoveler.MessageQueueProtocol. Expected \"amqp\" or \"stomp\", got %s", c.MQ)
	}
	var err error
	if c.MQ == "amqp" {
		c.AmqpURL, err = url.Parse(param.Shoveler_URL.GetString())
		if err != nil {
			return fmt.Errorf("Error parsing Shoveler.URL for AMQP: %s \n", err)
		}
		log.Debugln("AMQP URL:", c.AmqpURL.String())

		// Get the AMQP Exchange
		c.AmqpExchange = param.Shoveler_AMQPExchange.GetString()
		log.Debugln("AMQP Exchange:", c.AmqpExchange)

		c.AmqpToken = param.Shoveler_AMQPTokenLocation.GetString()
		log.Debugln("AMQP Token location:", c.AmqpToken)
		_, err := os.Stat(c.AmqpToken)
		if err != nil {
			return fmt.Errorf("Token in Shoveler.AMQPTokenLocation does not exists: %s", err.Error())
		}
		tokenContents, err := os.ReadFile(c.AmqpToken)
		if err != nil {
			return fmt.Errorf("Unable to read file: %s", c.AmqpToken)
		}
		if strings.TrimSpace(string(tokenContents)) == "" {
			return fmt.Errorf("Token content is empty. Reading from Shoveler.AMQPTokenLocation at %s", c.AmqpToken)
		}
	} else { // Stomp
		viper.SetDefault("Shoveler.Topic", "xrootd.shoveler")

		c.StompUser = param.Shoveler_StompUsername.GetString()
		log.Debugln("STOMP User:", c.StompUser)
		c.StompPassword = param.Shoveler_StompPassword.GetString()

		// Get the STOMP URL
		c.StompURL, err = url.Parse(param.Shoveler_URL.GetString())
		if err != nil {
			return fmt.Errorf("Error parsing Shoveler.URL for STOMP: %s \n", err)
		}
		log.Debugln("STOMP URL:", c.StompURL.String())

		c.StompTopic = param.Shoveler_Topic.GetString()
		log.Debugln("STOMP Topic:", c.StompTopic)

		// Get the STOMP cert
		c.StompCert = param.Shoveler_StompCert.GetString()
		log.Debugln("STOMP CERT:", c.StompCert)

		// Get the STOMP certkey
		c.StompCertKey = param.Shoveler_StompCertKey.GetString()
		log.Debugln("STOMP CERTKEY:", c.StompCertKey)
	}

	c.DestUdp = param.Shoveler_OutputDestinations.GetStringSlice()
	logLevel, err := log.ParseLevel(param.Logging_Level.GetString())
	if err != nil {
		return errors.Wrap(err, "Issue parsing specified log level")
	}
	if logLevel == log.DebugLevel {
		c.Debug = true
	} else {
		c.Debug = false
	}
	c.Verify = param.Shoveler_VerifyHeader.GetBool()

	ipMappings := []ipMappingItem{}
	if err := param.Shoveler_IPMapping.Unmarshal(&ipMappings); err != nil {
		return errors.Wrap(err, "Error reading Shoveler.IPMapping")
	}

	for idx, item := range ipMappings {
		if idx == 0 {
			if item.All != "" && item.Source == "" && item.Dest == "" {
				mapAll = item.All
				break
			} else if item.All != "" && (item.Source != "" || item.Dest != "") {
				return fmt.Errorf("Error decoding Shoveler.IPMapping. \"All\" and \"Source\"/\"Dest\" can't be both present: %s", item)
			} else { // item.All == ""
				ipMap[item.Source] = item.Dest
			}
		} else {
			ipMap[item.Source] = item.Dest
		}
	}

	// Set to false as Pelican runs Prometheus instance already
	c.Metrics = false
	return nil
}

// mapIp returns the mapped IP address
func mapIp(remote *net.UDPAddr) string {
	if mapAll != "" {
		return mapAll
	}
	if len(ipMap) == 0 {
		return remote.IP.String()
	}
	if ip, ok := ipMap[remote.IP.String()]; ok {
		return ip
	}
	return remote.IP.String()
}

func packageUdp(packet []byte, remote *net.UDPAddr) ([]byte, error) {
	msg := shoveler.Message{}
	// Base64 encode the packet
	str := base64.StdEncoding.EncodeToString(packet)
	msg.Data = str

	// add the remote
	msg.Remote = mapIp(remote)
	msg.Remote += ":" + strconv.Itoa(remote.Port)

	msg.ShovelerVersion = shoveler.ShovelerVersion

	b, err := json.Marshal(msg)

	if err != nil {
		return nil, errors.Wrap(err, "Failed to Marshal the msg to json")
	}
	return b, nil
}

func LaunchShoveler(ctx context.Context, egrp *errgroup.Group, metricsPort int) (int, error) {
	shovelerLogger = log.WithField("component", "shoveler")
	shoveler.SetLogger(shovelerLogger)

	config := shoveler.Config{}
	if err := configShoveler(&config); err != nil {
		return -1, err
	}

	shovelerLogger.Infoln("Starting xrootd-monitoring-shoveler...")

	viper.Set("queue_directory", param.Shoveler_QueueDirectory.GetString())

	// Start the message queue
	cq := shoveler.NewConfirmationQueue()

	if config.MQ == "amqp" {
		// Start the AMQP go func
		go shoveler.StartAMQP(&config, cq)
	} else if config.MQ == "stomp" {
		// Start the STOMP go func
		go shoveler.StartStomp(&config, cq)
	}

	lower := param.Shoveler_PortLower.GetInt()
	higher := param.Shoveler_PortHigher.GetInt()

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
		shovelerLogger.Warningln("Failed to set read buffer size to 1 MB:", err)
	}

	// Create the UDP forwarding destinations
	var udpDestinations []net.Conn

	// By default, forward to metrics endpoint for Prometheus metrics
	// TODO: integrate metrics to shoveler and remove the forwarding
	metricsEndpoint := fmt.Sprint("127.0.0.1:", metricsPort)
	udpConn, err := net.Dial("udp", metricsEndpoint)
	if err != nil {
		shovelerLogger.Warningln("Unable to connect to metrics endpoint:", metricsEndpoint, err)
	}
	udpDestinations = append(udpDestinations, udpConn)

	if len(config.DestUdp) > 0 {
		for _, dest := range config.DestUdp {
			udpConn, err := net.Dial("udp", dest)
			if err != nil {
				shovelerLogger.Warningln("Unable to parse destination:", dest, "Will not forward UDP packets to this destination:", err)
			}
			udpDestinations = append(udpDestinations, udpConn)
			shovelerLogger.Infoln("Adding udp forward destination:", dest)
		}
	}

	// Stop automatic eviction at shutdown
	egrp.Go(func() error {
		<-ctx.Done()
		err := conn.Close() // This will cause an net.ErrClosed in the goroutine below
		if err != nil {
			shovelerLogger.Errorln("Error closing UDP connection:", err)
		} else {
			log.Infoln("Xrootd monitoring shoveler has been stopped")
		}
		return nil
	})

	go func() {
		var buf [65536]byte
		for {
			rlen, remote, err := conn.ReadFromUDP(buf[:])

			if errors.Is(err, net.ErrClosed) {
				return
			} else if err != nil {
				// output errors
				shovelerLogger.Errorln("Failed to read from UDP connection:", err)
				// If we failed to read from the UDP connection, I'm not
				// sure what to do, maybe just continue as if nothing happened?
				continue
			}
			shoveler.PacketsReceived.Inc()

			if config.Verify && !shoveler.VerifyPacket(buf[:rlen]) {
				shoveler.ValidationsFailed.Inc()
				continue
			}

			msg, err := packageUdp(buf[:rlen], remote)
			if err != nil {
				shovelerLogger.Error(err)
			}

			// Send the message to the queue
			shovelerLogger.Debugln("Sending msg:", string(msg))
			cq.Enqueue(msg)

			// Send to the UDP destinations
			if len(udpDestinations) > 0 {
				for _, udpConn := range udpDestinations {
					_, err := udpConn.Write(msg)
					if err != nil {
						shovelerLogger.Errorln("Failed to send message to UDP destination "+udpConn.RemoteAddr().String()+":", err)
					}
				}
			}

		}
	}()

	return addr.Port, nil
}
