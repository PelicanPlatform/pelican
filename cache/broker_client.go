//go:build !windows

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

package cache

import (
	"bufio"
	"context"
	"encoding/json"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/broker"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

type (
	xrootdBrokerRequest struct {
		BrokerURL  string `json:"broker_url"`
		OriginName string `json:"origin"`
		Prefix     string `json:"prefix"`
		err        error
	}

	xrootdBrokerResp struct {
		Status string `json:"status"`
	}
)

// Given revConn, a reversed connection from the origin, send it to
// the xrootd process over the xrdConn unix socket
func sendXrootdSocket(xrdConn *net.UnixConn, revConn *net.TCPConn) error {
	defer revConn.Close()
	revFile, err := revConn.File()
	if err != nil {
		return errors.Wrap(err, "Unable to get file descriptor from socket for xrootd process")
	}
	log.Debugf("Sending TCP socket %d to XRootD", int(revFile.Fd()))
	oob := syscall.UnixRights(int(revFile.Fd()))
	if _, _, err := xrdConn.WriteMsgUnix([]byte(`{"status": "success"}`), oob, nil); err != nil {
		return errors.Wrap(err, "Failed to send file descriptor back to the xrootd process")
	}
	return nil
}

func sendXrootdError(xrdConn net.Conn, msg string) {
	resp := xrootdBrokerResp{Status: msg}
	respBytes, err := json.Marshal(resp)
	if err != nil {
		log.Warning("Unable to convert response to JSON:", err)
		return
	}
	if _, err = xrdConn.Write(respBytes); err != nil {
		log.Warning("Unable to send error message to xrootd:", err)
		return
	}
}

// Take a Unix socket connected to the XCache instance, read off the
// request, and then perform a connection reversal as appropriate
func handleRequest(ctx context.Context, xrdConn net.Conn) {
	scanner := bufio.NewScanner(xrdConn)
	defer xrdConn.Close()
	brokerChannel := make(chan xrootdBrokerRequest)

	unixConn, ok := xrdConn.(*net.UnixConn)
	if !ok {
		errStr := "Internal error: xrootd connection not a Unix socket"
		log.Warning(errStr)
		sendXrootdError(xrdConn, errStr)

	}

	// Reading from the channel is done as a separate goroutine; once a request is found, it
	// is sent to the parent routine.  This allows us to select on the context as well; if the
	// the context is canceled, the parent routine will close the socket, causing an error in the
	// child.
	go func() {
		xrdReq := xrootdBrokerRequest{}
		if !scanner.Scan() {
			log.Warning("Failed to read JSON request from xrootd")
			xrdReq.err = errors.New("Failed to read JSON request from xrootd")
		} else if err := json.Unmarshal(scanner.Bytes(), &xrdReq); err != nil {
			xrdReq.err = err
		}
		brokerChannel <- xrdReq
	}()
	select {
	case <-ctx.Done():
		sendXrootdError(xrdConn, "Pelican shutting down")
		return
	case xrdReq := <-brokerChannel:
		if xrdReq.err != nil {
			errStr := "Failure when handling broker request from xrootd: " + xrdReq.err.Error()
			log.Warning(errStr)
			sendXrootdError(xrdConn, errStr)
			return
		}
		newConn, err := broker.ConnectToOrigin(ctx, xrdReq.BrokerURL, xrdReq.Prefix, xrdReq.OriginName)
		if err != nil {
			errStr := "Failure when getting connection reversal from origin: " + err.Error()
			log.Warning(errStr)
			sendXrootdError(xrdConn, errStr)
			return
		}
		tcpConn, ok := newConn.(*net.TCPConn)
		if !ok {
			errStr := "Internal error: reverse connection does not appear to be a TCP socket"
			log.Warning(errStr)
			sendXrootdError(xrdConn, errStr)
			return
		}

		if err = sendXrootdSocket(unixConn, tcpConn); err != nil {
			log.Warning("Failure when sending file descriptor to xrootd:", err)
		}
	}
}

// Launch a goroutine that listens for socket reversal requests from the XRootD daemon
func LaunchRequestListener(ctx context.Context, egrp *errgroup.Group) error {
	socketName := filepath.Join(param.Cache_RunLocation.GetString(), "cache-reversal.sock")
	if len(socketName) > 104 {
		return errors.Errorf("Unix socket name, %s, is too long; cannot be more than 104 characters", socketName)
	}
	userInfo, err := config.GetDaemonUserInfo()
	if err != nil {
		return err
	}
	err = os.Remove(socketName)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return errors.Wrapf(err, "Failed to cleanup Unix socket %s", socketName)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketName, Net: "unix"})
	if err != nil {
		return errors.Wrapf(err, "Failed to listen on Unix socket %s", socketName)
	}

	if err = os.Chmod(socketName, os.FileMode(0700)); err != nil {
		listener.Close()
		return errors.Wrapf(err, "Failed to set correct mode for Unix socket %s", socketName)
	}
	if err = os.Chown(socketName, userInfo.Uid, userInfo.Gid); err != nil {
		listener.Close()
		return errors.Wrap(err, "Failed to set ownership for Unix socket")
	}

	connChannel := make(chan net.Conn)
	egrp.Go(func() (err error) {
		for {
			var conn net.Conn
			conn, err = listener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					err = nil
				}
				return err
			}
			select {
			case <-ctx.Done():
				return
			case connChannel <- conn:
			}
		}
	})
	egrp.Go(func() (err error) {
		defer listener.Close()
		defer func() {
			err = os.Remove(socketName)
			if err != nil {
				log.Errorln("Error when cleaning up listener socket:", err)
			}
		}()
		for {
			select {
			case <-ctx.Done():
				return
			case conn := <-connChannel:
				go handleRequest(ctx, conn)
			}
		}
	})
	return nil
}
