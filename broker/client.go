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
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token_scopes"
)

type (

	// Struct handling the cache's response to the origin's reversal
	// callback.
	reversalCallbackResponse struct {
		Certificate string `json:"certificate"`
	}

	// Represents a connection we may want to hijack.  The default transport
	// will create these connections and we'll later reverse them
	hijackConn struct {
		*net.TCPConn
		realConn *net.TCPConn
		// blockReads is set to true to make Read() return a timeout error immediately.
		// This prevents the HTTP transport's background TLS reader from consuming
		// data that we need after hijacking the connection.
		blockReads atomic.Bool
	}

	// A listener that reverses an existing, connected TCP socket.  One can
	// call 'accept' once (which will immediately return the provided TCP
	// socket); subsequent Accept calls will return net.ErrClosed.
	oneShotListener struct {
		conn atomic.Pointer[net.TCPConn]
		addr net.Addr
	}

	// Struct holding pending requests waiting on an origin callback
	pendingReversals struct {
		channel chan http.ResponseWriter
		prefix  string
	}
)

var (
	responseMapLock sync.Mutex                  = sync.Mutex{}
	response        map[string]pendingReversals = make(map[string]pendingReversals)
)

const requestIdBytes = "abcdefghijklmnopqrstuvwxyz0123456789"

// ResetState clears all pending broker requests; used for testing
func ResetState() {
	responseMapLock.Lock()
	defer responseMapLock.Unlock()
	// Close all pending channels to unblock any waiting goroutines
	for _, pending := range response {
		close(pending.channel)
	}
	response = make(map[string]pendingReversals)

	// Note: We don't touch namespaceKeys here. The errgroup cleanup goroutine
	// in LaunchNamespaceKeyMaintenance will call Stop(), DeleteAll(), and set it to nil
	// when the context is cancelled. Touching it here would create a race condition.
}

func (hj *hijackConn) Close() error {
	return nil
}

// Read checks if reads are blocked before delegating to the underlying connection.
// When blockReads is set, it returns a timeout error to stop the HTTP transport's
// background TLS reader from consuming data we need after hijacking.
func (hj *hijackConn) Read(b []byte) (n int, err error) {
	if hj.blockReads.Load() {
		return 0, os.ErrDeadlineExceeded
	}
	return hj.TCPConn.Read(b)
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
		return
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

func generatePrivateKey() (keyContents string, priv *ecdsa.PrivateKey, err error) {

	priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
func ConnectToService(ctx context.Context, brokerUrl, prefix, originName string) (conn net.Conn, err error) {

	// Ensure we have a local CA for signing an origin host certificate.
	if err = config.GenerateCACert(); err != nil {
		return
	}
	caCert, err := config.LoadCertificate(param.Server_TLSCACertificateFile.GetString())
	if err != nil {
		return
	}
	caPrivateKey, err := config.LoadPrivateKey(param.Server_TLSCAKey.GetString(), true)
	if err != nil {
		return
	}

	keyContents, privKey, err := generatePrivateKey()
	if err != nil {
		return
	}

	reqC := reversalRequest{
		RequestId:   generateRequestId(),
		PrivateKey:  keyContents,
		CallbackUrl: param.Server_ExternalWebUrl.GetString() + "/api/v1.0/broker/callback",
		OriginName:  originName,
		Prefix:      prefix,
	}
	logFields := log.Fields{"request_id": reqC.RequestId, "origin": originName, "prefix": prefix}
	reqBytes, err := json.Marshal(&reqC)
	if err != nil {
		return
	}

	reqReader := strings.NewReader(string(reqBytes))

	responseChannel := make(chan http.ResponseWriter)
	defer close(responseChannel)
	responseMapLock.Lock()
	response[reqC.RequestId] = pendingReversals{channel: responseChannel, prefix: prefix}
	responseMapLock.Unlock()
	defer func() {
		responseMapLock.Lock()
		defer responseMapLock.Unlock()
		delete(response, reqC.RequestId)
	}()

	// Send a request to the broker for a connection reversal
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, brokerUrl, reqReader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "pelican-cache/"+config.GetVersion())

	brokerAud, err := url.Parse(brokerUrl)
	if err != nil {
		err = errors.Wrap(err, "failure when constructing the broker audience URL")
		return
	}
	brokerAud.RawQuery = ""
	brokerAud.Path = ""

	token, err := createToken(prefix, param.Server_Hostname.GetString(), brokerAud.String(), token_scopes.Broker_Reverse)
	if err != nil {
		err = errors.Wrap(err, "failure when constructing the broker request token")
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)

	// Create a cloned transport which disables HTTP/2 (as that TCP string can't
	// be hijacked which we will need to do below).  The clone ensures that we're
	// not going to be reusing TCP connections.
	tr := config.GetBasicTransport().Clone()
	tr.TLSNextProto = make(map[string]func(string, *tls.Conn) http.RoundTripper)
	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		err = errors.Wrap(err, "failure when invoking the broker URL")
		return
	}
	defer resp.Body.Close()
	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		err = errors.Wrap(err, "failure when reading response from broker response")
	}
	if resp.StatusCode >= 400 {
		errResp := server_structs.SimpleApiResp{}
		log.Errorf("Failure (status code %d) when invoking the broker: %s", resp.StatusCode, string(responseBytes))
		if err = json.Unmarshal(responseBytes, &errResp); err != nil {
			err = errors.Errorf("failure when invoking the broker (status code %d); unable to parse error message", resp.StatusCode)
		} else {
			err = errors.Errorf("failure when invoking the broker (status code %d): %s", resp.StatusCode, errResp.Msg)
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
	// Strip port from originName for DNS name (hostname:port -> hostname)
	dnsName := originName
	if host, _, err := net.SplitHostPort(originName); err == nil {
		dnsName = host
	}
	template.DNSNames = []string{dnsName}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &privKey.PublicKey, caPrivateKey)
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
	defer tck.Stop()
	log.WithFields(logFields).Debug("Cache waiting for up to 20 seconds for origin to callback")
	select {
	case <-ctx.Done():
		log.WithFields(logFields).Debug("Context has been cancelled while waiting for callback")
		err = ctx.Err()
		return
	case <-tck.C:
		log.WithFields(logFields).Warn("Request has timed out when waiting for callback from origin")
		err = errors.Errorf("Timeout when waiting for callback from origin")
		return
	case writer := <-responseChannel:
		hj, ok := writer.(http.Hijacker)
		if !ok {
			log.WithFields(logFields).Error("Not able to hijack underlying TCP connection from server")
			resp := server_structs.SimpleApiResp{
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

		// Write headers including explicit length, then flush out the body.
		// If we don't do both items, the response may still be buffered by time
		// we hijack the connection, leading to a client that indefinitely waits.
		writer.Header().Set("Content-Length", strconv.Itoa(len(callbackBytes)))
		writer.WriteHeader(http.StatusOK)
		if _, err = writer.Write(callbackBytes); err != nil {
			log.Error("Failed to write callback response to client:", err)
			return
		}
		flusher, ok := writer.(http.Flusher)
		if !ok {
			log.Error("Unable to flush data to client")
			return
		}
		flusher.Flush()

		conn, _, err = hj.Hijack()
		if err != nil {
			log.WithFields(logFields).WithError(err).Error("Failed to hijack connection")
			return
		}
		tlsConn, ok := conn.(*tls.Conn)
		if ok {
			// Once the cache receives the HTTP response, it'll close the TLS connection
			// That will cause a "close notify" to be sent back to the origin (this goroutine),
			// which indicates the last TLS record has been received.  That will cause an EOF
			// to be read from the TLS socket.
			bytesRead := 0
			for {
				ignoreBytes := make([]byte, 1024)
				n, readErr := tlsConn.Read(ignoreBytes)
				bytesRead += n
				if errors.Is(readErr, io.EOF) {
					break
				} else if readErr != nil {
					log.WithFields(logFields).WithError(readErr).Errorf("Failed to get close notification from origin after reading %d bytes", bytesRead)
					err = readErr
					return
				}
			}
			conn = tlsConn.NetConn()
			tcpConn, ok := conn.(*net.TCPConn)
			if !ok {
				tlsConn.Close()
				log.WithFields(logFields).Error("Remote connection is not over TCP")
				return
			}
			var fp *os.File
			fp, err = tcpConn.File()
			// Close the TCP connection out from underneath the TLS socket, preventing it
			// from sending spurious TLS records to the remote side and confusing it.
			tcpConn.Close()
			if err != nil {
				log.WithFields(logFields).WithError(err).Error("Failed to duplicate TCP connection")
				return
			}
			defer fp.Close()
			conn, err = net.FileConn(fp)
			if err != nil {
				log.WithFields(logFields).WithError(err).Error("Failed to convert file pointer to a TCP connection")
				return
			}
		}
	}
	return
}

// Callback to a given cache based on the request we got from a broker.
//
// The TCP socket used for the callback will be converted to a one-shot listener
// and reused with the origin as the "server".
func doCallback(ctx context.Context, sType server_structs.ServerType, brokerResp reversalRequest) (listener net.Listener, err error) {
	logFields := log.Fields{"request_id": brokerResp.RequestId, "callback_url": brokerResp.CallbackUrl}
	log.WithFields(logFields).Debug("Origin starting callback to cache")

	privateKey, err := privateKeyFromBytes(brokerResp.PrivateKey)
	if err != nil {
		return
	}
	callbackReq := callbackRequest{RequestId: brokerResp.RequestId}
	reqBytes, err := json.Marshal(&callbackReq)
	if err != nil {
		return
	}
	reqReader := bytes.NewReader(reqBytes)
	var req *http.Request
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, brokerResp.CallbackUrl, reqReader)
	if err != nil {
		return
	}

	dur := time.Duration(5*time.Second - time.Duration(mrand.Intn(500))*time.Millisecond)
	req.Header.Set("X-Pelican-Timeout", dur.String())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "pelican-origin/"+config.GetVersion())

	cacheAud, err := url.Parse(brokerResp.CallbackUrl)
	if err != nil {
		return
	}
	cacheAud.Path = ""

	servicePrefix := ""
	url, err := url.Parse(param.Server_ExternalWebUrl.GetString())
	if err != nil {
		err = errors.Wrap(err, "failure when parsing the external web URL")
		return
	}
	if sType.IsEnabled(server_structs.CacheType) {
		servicePrefix = server_structs.GetCacheNs(url.Hostname())
	} else {
		servicePrefix = server_structs.GetOriginNs(url.Host)
	}
	token, err := createToken(servicePrefix, url.Hostname(), cacheAud.String(), token_scopes.Broker_Callback)
	if err != nil {
		err = errors.Wrap(err, "failure when constructing the cache callback token")
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)

	// Create a copy of the default transport; instead of using the existing connection pool,
	// we will use a custom connection pool where we can hijack connections
	tr := config.GetTransport().Clone()
	hijackConnList := make([]*hijackConn, 0)
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
		// Take the connection and stash it onto our list.  After the client has shutdown, we will
		// steal the last TCP connection
		hj := &hijackConn{tcpConn, tcpConn, atomic.Bool{}}
		hijackConnMutex.Lock()
		hijackConnList = append(hijackConnList, hj)
		hijackConnMutex.Unlock()
		return hj, nil
	}

	// Cleanup any connections.  If we decide to steal one of them,
	// we will set hj.realConn to nil.
	defer func() {
		hijackConnMutex.Lock()
		defer hijackConnMutex.Unlock()
		for _, hj := range hijackConnList {
			if hj.realConn != nil {
				hj.realConn.Close()
			}
		}
	}()

	client := &http.Client{Transport: tr}
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
		errResp := server_structs.SimpleApiResp{}
		if err = json.Unmarshal(responseBytes, &errResp); err != nil {
			err = errors.Errorf("Failure when invoking cache %s callback (status code %d); unable to parse error message", brokerResp.CallbackUrl, resp.StatusCode)
		} else {
			err = errors.Errorf("Failure when invoking cache %s callback (status code %d): %s", brokerResp.CallbackUrl, resp.StatusCode, errResp.Msg)
		}
		log.WithFields(logFields).WithError(err).Error("Callback failed")
		return
	}

	log.WithFields(logFields).Debug("Origin received callback response from cache")
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

	// Before sending close notify, block reads on the hijacked connection.
	// This is critical: the HTTP transport may have a background goroutine doing tls.Read()
	// which internally reads from our hijacked TCP connection. If we don't stop that reader,
	// it will consume the TLS ClientHello that the cache sends after receiving our close_notify,
	// causing the subsequent TLS handshake to fail.
	hijackConnMutex.Lock()
	var lastHj *hijackConn
	if len(hijackConnList) > 0 {
		lastHj = hijackConnList[len(hijackConnList)-1]
		lastHj.blockReads.Store(true)
		if err := lastHj.realConn.SetReadDeadline(time.Now()); err != nil {
			log.WithFields(logFields).WithError(err).Warn("Failed to set read deadline to stop TLS reader")
		}
	}
	hijackConnMutex.Unlock()

	// Send the "close notify" packet to the cache
	client.CloseIdleConnections()
	log.WithFields(logFields).Debugln("Sent close notify to cache; hijacking connection")

	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{hostCertificate},
			PrivateKey:  privateKey,
		}},
		NextProtos: []string{"http/1.1"},
	}

	var hj *hijackConn
	gotConn := false
	hijackConnMutex.Lock()
	if len(hijackConnList) > 0 {
		hj = hijackConnList[len(hijackConnList)-1]
		gotConn = true
	}
	hijackConnMutex.Unlock()
	if !gotConn {
		err = errors.New("Internal error: no new connection made to remote cache")
		log.WithFields(logFields).WithError(err).Error("No connection available to hijack")
		return
	}

	// Create a new socket from the old socket; resets state in the
	// runtime to make it more like a "new" socket.
	fp, err := hj.realConn.File()
	if err != nil {
		err = errors.Wrap(err, "Failure when duplicating hijacked connection")
		log.WithFields(logFields).WithError(err).Error("Failed to duplicate hijacked connection")
		return
	}
	hj.realConn.Close()
	newConn, err := net.FileConn(fp)
	if err != nil {
		err = errors.Wrap(err, "Failure when making socket from duplicated connection")
		log.WithFields(logFields).WithError(err).Error("Failed to create connection from file descriptor")
		return
	}
	fp.Close()
	revConn, ok := newConn.(*net.TCPConn)
	if !ok {
		err = errors.New("Failed to cast connection back to TCP socket")
		log.WithFields(logFields).WithError(err).Error("Connection is not TCP")
		return
	}

	hj.realConn = nil
	listener = tls.NewListener(newOneShotListener(revConn), &tlsConfig)

	return
}

// Launch a goroutine that polls the broker endpoint for reversal requests
// The returned channel will produce listeners that are "one shot"; it's a
// TLS listener where you can invoke "Accept" once before it automatically
// closes itself.  It is the result of a successful connection reversal to
// a cache.
//
// The request monitor is used by the "private service" (the service behind the
// firewall) to know when to setup connections requested by the "public service"
// (e.g., a cache).
//
// The registeredPrefix parameter, if non-empty, specifies the namespace prefix
// to use for token authentication. This should be the prefix that the service
// is registered under in the registry. If empty, the prefix is constructed from
// privateName. This is useful when polling for multiple addresses (e.g., both
// web URL and XRootD URL) but authenticating with a single registered namespace.
func LaunchRequestMonitor(ctx context.Context, egrp *errgroup.Group, sType server_structs.ServerType, privateName, registeredPrefix string, resultChan chan any) (err error) {
	fedInfo, err := config.GetFederation(ctx)
	if err != nil {
		return err
	}

	// Use the provided registeredPrefix for authentication if specified,
	// otherwise construct it from privateName
	prefix := registeredPrefix
	if prefix == "" {
		if sType.IsEnabled(server_structs.CacheType) {
			prefix = server_structs.GetCacheNs(privateName)
		} else {
			prefix = server_structs.GetOriginNs(privateName)
		}
	}

	brokerUrl := fedInfo.BrokerEndpoint
	if brokerUrl == "" {
		return errors.New("Broker service is not set or discovered; cannot enable broker functionality.  Try setting Federation.BrokerUrl")
	}
	brokerEndpoint := brokerUrl + "/api/v1.0/broker/retrieve"
	oReq := originRequest{
		Origin: privateName,
		Prefix: prefix,
	}
	req, err := json.Marshal(&oReq)
	if err != nil {
		return
	}
	reqReader := bytes.NewReader(req)

	// Create a token that will be used to retrieve requests from the broker;
	// this is done before the goroutine starts to guarantee that we are looking up
	// the Viper config from a single-threaded context.  Otherwise, during startup,
	// we may have concurrent read and write operations to the Viper config, which
	// can lead to a panic.
	brokerAud, err := url.Parse(fedInfo.BrokerEndpoint)
	if err != nil {
		log.Errorln("Failure when parsing broker URL:", err)
		return
	}
	brokerAud.Path = ""
	token, err := createToken(prefix, param.Server_Hostname.GetString(), brokerAud.String(), token_scopes.Broker_Retrieve)
	if err != nil {
		log.Errorln("Failure when constructing the broker retrieve token:", err)
		return
	}

	client := &http.Client{Transport: config.GetBasicTransport()}

	egrp.Go(func() (err error) {
		firstLoop := true
		for {
			sleepDuration := time.Second + time.Duration(mrand.Intn(500))*time.Microsecond
			select {
			case <-ctx.Done():
				return nil
			default:
				// Send a request to the broker for a connection reversal
				reqReader.Reset(req)
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, brokerEndpoint, reqReader)
				if err != nil {
					log.Errorln("Failure when creating new broker URL request:", err)
					break
				}

				dur := param.Transport_ResponseHeaderTimeout.GetDuration() - time.Duration(mrand.Intn(500))*time.Millisecond
				req.Header.Set("X-Pelican-Timeout", dur.String())
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("User-Agent", "pelican-origin/"+config.GetVersion())

				if !firstLoop {
					token, err = createToken(prefix, param.Server_Hostname.GetString(), brokerAud.String(), token_scopes.Broker_Retrieve)
					if err != nil {
						log.Errorln("Failure when constructing the broker retrieve token:", err)
						break
					}
				}
				firstLoop = false
				req.Header.Set("Authorization", "Bearer "+token)

				resp, err := client.Do(req)
				if err != nil {
					if errors.Is(err, context.Canceled) {
						break
					}
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
					errResp := server_structs.SimpleApiResp{}
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
				brokerResp := &brokerRetrievalResp{}
				if err = json.Unmarshal(responseBytes, &brokerResp); err != nil {
					log.Errorln("Failed to unmarshal response from origin retrieval:", err)
					break
				}

				if brokerResp.Status == server_structs.RespOK {
					listener, err := doCallback(ctx, sType, brokerResp.Request)
					if err != nil {
						if errors.Is(err, context.Canceled) {
							log.Debugln("Shutdown encountered while processing callback")
							return nil
						}
						log.Errorln("Failed to callback to the cache:", err)
						select {
						case <-ctx.Done():
							return nil
						case resultChan <- err:
							break
						}
						break
					}
					select {
					case <-ctx.Done():
						return nil
					case resultChan <- BrokerListener{
						Listener:  listener,
						RequestId: brokerResp.Request.RequestId,
					}:
						break
					}
				} else if brokerResp.Status == server_structs.RespFailed {
					log.Errorln("Broker responded to origin retrieve with an error:", brokerResp.Msg)
				} else if brokerResp.Status != server_structs.RespPollTimeout { // We expect timeouts; do not log them.
					if brokerResp.Msg != "" {
						log.Errorf("Broker responded with unknown status (%s); msg: %s", brokerResp.Status, brokerResp.Msg)
					} else {
						log.Errorf("Broker responded with unknown status %s", brokerResp.Status)
					}
				}
				sleepDuration = 0
			}
			time.Sleep(sleepDuration)
		}
	})
	return
}
