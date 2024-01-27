/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

package broker

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

type (

	// Struct representing the HTTP request for a connection reversal
	reversalRequestClient struct {
		RequestId  string `json:"req_id"`
		PrivateKey string `json:"private_key"`
	}

	// Struct handling the cache's response to the origin's reversal
	// callback.
	reversalCallbackResponse struct {
		Certificate string `json:"certificate"`
	}

	// Represents a connection we may want to hijack.  The default transport
	// will create these connections and we'll later reverse them
	hijackConn struct {
		net.Conn
		realConn *net.TCPConn
	}

	// A listener that reverses an existing, connected TCP socket.  One can
	// call 'accept' once (which will immediately return the provided TCP
	// socket); subsequent Accept calls will return net.ErrClosed.
	oneShotListener struct {
		conn atomic.Pointer[net.TCPConn]
		addr net.Addr
	}
)

var (
	responseMapLock sync.Mutex                          = sync.Mutex{}
	response        map[string]chan http.ResponseWriter = make(map[string]chan http.ResponseWriter)
)

const requestIdBytes = "abcdefghijklmnopqrstuvwxyz0123456789"

func (*hijackConn) Close() error {
	return nil
}

// Returns a new 'one shot listener' from a given TCP connection
func newOneShotListener(conn *net.TCPConn) net.Listener {
	listener := &oneShotListener{addr: conn.LocalAddr()}
	listener.conn.Store(conn)
	return listener
}

func (listener *oneShotListener) Accept() (conn net.Conn, err error) {
	tcpConn := listener.conn.Swap(nil)
	if tcpConn == nil {
		err = net.ErrClosed
	}
	conn = tcpConn
	return
}

func (listener *oneShotListener) Close() error {
	listener.conn.Swap(nil)
	return nil
}

func (listener *oneShotListener) Addr() net.Addr {
	return listener.addr
}

func generatePrivateKey() (keyContents string, err error) {

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}

	bytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return
	}

	keyContents = base64.StdEncoding.EncodeToString(bytes)
	return
}

// Given a base64-encoded private key (output from generatePrivateKey),
// construct a private key object
func privateKeyFromBytes(keyContents string) (pkey crypto.PrivateKey, err error) {
	keyBytes, err := base64.StdEncoding.DecodeString(keyContents)
	if err != nil {
		return
	}

	pkey, err = x509.ParsePKCS8PrivateKey(keyBytes)
	return
}

func generateRequestId() string {
	reqIdB := make([]byte, 10)
	for idx := range reqIdB {
		reqIdB[idx] = requestIdBytes[mrand.Intn(len(requestIdBytes))]
	}
	return string(reqIdB)
}

// Given an origin's broker URL, return a connected socket to the origin
func GetCallback(ctx context.Context, brokerUrl string, originName string) (conn net.Conn, err error) {

	// Ensure we have a local CA for signing an origin host certificate.
	if err = config.GenerateCACert(); err != nil {
		return
	}
	caCert, err := config.LoadCertficate(param.Server_TLSCACertificateFile.GetString())
	if err != nil {
		return
	}
	caPrivateKey, err := config.LoadPrivateKey(param.Server_TLSCAKey.GetString())
	if err != nil {
		return
	}

	keyContents, err := generatePrivateKey()
	if err != nil {
		return
	}

	reqC := reversalRequestClient{
		RequestId:  generateRequestId(),
		PrivateKey: keyContents,
	}
	reqBytes, err := json.Marshal(&reqC)
	if err != nil {
		return
	}

	reqReader := strings.NewReader(string(reqBytes))

	responseChannel := make(chan http.ResponseWriter)
	defer close(responseChannel)
	responseMapLock.Lock()
	response[reqC.RequestId] = responseChannel
	responseMapLock.Unlock()
	defer func() {
		responseMapLock.Lock()
		defer responseMapLock.Unlock()
		delete(response, reqC.RequestId)
	}()

	// Send a request to the broker for a connection reversal
	req, err := http.NewRequestWithContext(ctx, "POST", brokerUrl, reqReader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "pelican-cache/"+config.PelicanVersion)
	// TODO: set bearer token

	tr := config.GetTransport()
	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		err = errors.Wrap(err, "Failure when invoking the broker URL")
		return
	}
	defer resp.Body.Close()
	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		err = errors.Wrap(err, "Failure when reading response from broker response")
	}
	if resp.StatusCode >= 400 {
		errResp := brokerErrResp{}
		if err = json.Unmarshal(responseBytes, &errResp); err != nil {
			err = errors.Errorf("Failure when invoking the broker (status code %d); unable to parse error message", resp.StatusCode)
		} else {
			err = errors.Errorf("Failure when invoking the broker (status code %d): %s", resp.StatusCode, errResp.Msg)
		}
		return
	}

	// Connection request sent; create a new host certificate in preparation for a response.
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return
	}
	notBefore := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Pelican"},
			CommonName:   originName,
		},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(10 * time.Minute),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	template.DNSNames = []string{originName}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &(caPrivateKey.PublicKey), caPrivateKey)
	if err != nil {
		return
	}
	callbackResp := reversalCallbackResponse{
		Certificate: base64.StdEncoding.EncodeToString(derBytes),
	}
	callbackBytes, err := json.Marshal(&callbackResp)
	if err != nil {
		return
	}

	// Wait for the origin to callback to the cache's return endpoint; that HTTP handler
	// will write to the channel we originally posted.
	tck := time.NewTicker(20 * time.Second)
	select {
	case <-tck.C:
		err = errors.Errorf("Timeout when waiting for callback from origin")
		return
	case writer := <-responseChannel:
		hj, ok := writer.(http.Hijacker)
		if !ok {
			resp := brokerErrResp{
				Msg:    "Unable to reverse TCP connection; HTTP/2 in use",
				Status: "error",
			}
			var respBytes []byte
			respBytes, err = json.Marshal(&resp)
			if err != nil {
				respBytes = []byte("")
				log.Error("Failed to serialize broker response:", err)
			} else {
				writer.Header().Set("Content-Type", "application/json")
			}
			writer.WriteHeader(http.StatusBadRequest)
			_, err = writer.Write(respBytes)
			if err != nil {
				log.Error("Failed to write response to client:", err)
			}
			return
		}
		writer.WriteHeader(http.StatusOK)
		if _, err = writer.Write(callbackBytes); err != nil {
			log.Error("Failed to write callback response co client:", err)
			return
		}
		conn, _, err = hj.Hijack()
	}
	return
}

// Callback to a given cache based on the request we got from a broker
func doCallback(ctx context.Context, brokerResp reversalRequest) (listener net.Listener, err error) {

	privateKey, err := privateKeyFromBytes(brokerResp.PrivateKey)
	if err != nil {
		return
	}

	reqBytes, err := json.Marshal(&brokerResp)
	if err != nil {
		return
	}
	reqReader := bytes.NewReader(reqBytes)
	var req *http.Request
	req, err = http.NewRequestWithContext(ctx, "POST", brokerResp.CallbackUrl, reqReader)
	if err != nil {
		return
	}

	dur := time.Duration(5*time.Second - time.Duration(mrand.Intn(500))*time.Millisecond)
	req.Header.Set("X-Pelican-Timeout", dur.String())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "pelican-origin/"+config.PelicanVersion)

	// TODO: set bearer token

	// Create a copy of the default transport; instead of using the existing connection pool,
	// we will use a custom connection pool where we can hijack connections
	tr := *config.GetTransport()
	hijackConnList := make([]hijackConn, 0)
	hijackConnMutex := sync.Mutex{}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := net.Dialer{}
		conn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return conn, err
		}
		tcpConn, ok := conn.(*net.TCPConn)
		if !ok {
			return conn, nil
		}
		hj := hijackConn{conn, tcpConn}
		hijackConnMutex.Lock()
		hijackConnList = append(hijackConnList, hj)
		hijackConnMutex.Unlock()
		return &hj, nil
	}
	client := &http.Client{Transport: &tr}
	resp, err := client.Do(req)
	if err != nil {
		err = errors.Wrapf(err, "Failure when calling back to cache %s for a reversal request", brokerResp.CallbackUrl)
		return
	}
	defer resp.Body.Close()
	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		err = errors.Wrapf(err, "Failure when reading response from callback to cache %s", brokerResp.CallbackUrl)
		return
	}

	if resp.StatusCode >= 400 {
		errResp := brokerErrResp{}
		if err = json.Unmarshal(responseBytes, &errResp); err != nil {
			err = errors.Errorf("Failure when invoking cache %s callback (status code %d); unable to parse error message", brokerResp.CallbackUrl, resp.StatusCode)
		} else {
			err = errors.Errorf("Failure when invoking cache %s callback (status code %d): %s", brokerResp.CallbackUrl, resp.StatusCode, errResp.Msg)
		}
		return
	}

	callbackResp := reversalCallbackResponse{}
	if err = json.Unmarshal(responseBytes, &callbackResp); err != nil {
		err = errors.Wrapf(err, "Failed to parse cache %s callback response", brokerResp.CallbackUrl)
		return
	}

	hostCertificate, err := base64.StdEncoding.DecodeString(callbackResp.Certificate)
	if err != nil {
		err = errors.Wrapf(err, "Failed to decode the cache %s certificate in response", brokerResp.CallbackUrl)
		return
	}

	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{hostCertificate},
			PrivateKey:  privateKey,
		}},
	}

	hijackConnMutex.Lock()
	hj := hijackConnList[len(hijackConnList)-1]
	hijackConnMutex.Unlock()

	listener = tls.NewListener(newOneShotListener(hj.realConn), &tlsConfig)

	return
}

// Launch a goroutine that polls the broker endpoint for reversal requests
// The returned channel will produce listeners that are "one shot"; it's a
// TLS listener where you can invoke "Accept" once before it automatically
// closes itself.  It is the result of a successful connection reversal to
// a cache.
func LaunchRequestMonitor(ctx context.Context, egrp *errgroup.Group, resultChan chan net.Listener) (err error) {
	brokerUrl := param.Federation_BrokerUrl.GetString() + "/api/v1.0/broker/retrieve"
	originUrl, err := url.Parse(param.Server_ExternalWebUrl.GetString())
	if err != nil {
		return
	}
	oReq := originRequest{
		Origin: originUrl.Hostname(),
		Prefix: param.Origin_NamespacePrefix.GetString(),
	}
	req, err := json.Marshal(&oReq)
	if err != nil {
		return
	}
	reqReader := bytes.NewReader(req)

	egrp.Go(func() (err error) {
		for {
			sleepDuration := time.Second + time.Duration(mrand.Intn(500))*time.Microsecond
			select {
			case <-ctx.Done():
				return
			default:
				// Send a request to the broker for a connection reversal
				reqReader.Reset(req)
				req, err := http.NewRequestWithContext(ctx, "POST", brokerUrl, reqReader)
				if err != nil {
					log.Errorln("Failure when creating new broker URL request:", err)
					break
				}

				dur := time.Duration(5*time.Second - time.Duration(mrand.Intn(500))*time.Millisecond)
				req.Header.Set("X-Pelican-Timeout", dur.String())
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("User-Agent", "pelican-origin/"+config.PelicanVersion)

				// TODO: set bearer token

				tr := config.GetTransport()
				client := &http.Client{Transport: tr}

				resp, err := client.Do(req)
				if err != nil {
					log.Errorln("Failure when invoking the broker URL for retrieving requests", err)
					break
				}
				defer resp.Body.Close()
				responseBytes, err := io.ReadAll(resp.Body)
				if err != nil {
					log.Errorln("Failure when reading from broker response:", err)
					break
				}
				if resp.StatusCode >= 400 {
					errResp := brokerErrResp{}
					if err = json.Unmarshal(responseBytes, &errResp); err != nil {
						log.Errorf("Failure when invoking the broker (status code %d); unable to parse error message", resp.StatusCode)
					} else {
						log.Errorf("Failure when invoking the broker (status code %d): %s", resp.StatusCode, errResp.Msg)
					}
					break
				} else if resp.StatusCode >= 300 { // 3xx responses should be handled internally.
					log.Errorf("Unknown response status code: %d", resp.StatusCode)
					break
				}
				brokerResp := &originResp{}
				if err = json.Unmarshal(responseBytes, &brokerResp); err != nil {
					log.Errorln("Failed to unmarshal response from origin retrieval:", err)
					break
				}

				conn, err := doCallback(ctx, brokerResp.Request)
				if err != nil {
					log.Errorln("Failed to callback to the cache:", err)
					break
				}
				resultChan <- conn
				sleepDuration = 0
			}
			time.Sleep(sleepDuration)
		}
	})
	return
}
