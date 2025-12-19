package p11proxy

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/go-p11-kit/p11kit"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

// Info contains the outputs needed by a developer to wire OpenSSL to the helper.
// All paths are absolute.
type Info struct {
	Enabled         bool
	ServerAddress   string // value to export as P11_KIT_SERVER_ADDRESS, e.g., unix:path=/tmp/p11-kit/pkcs11-<pid>.sock
	PKCS11URL       string // e.g., pkcs11:token=pelican-tls;object=server-key;type=private
	OpenSSLConfPath string // generated OpenSSL engine config path
	CertPath        string // path to certificate chain for -cert
	ModulePath      string // path to p11-kit client module
}

// Options controls Start behavior. All fields are optional.
// If a field is empty, sensible defaults or autodetection are used.
// No secrets should be included here.
type Options struct {
	// TokenLabel is the PKCS#11 token label exposed to the client.
	TokenLabel string
	// ObjectLabel is the PKCS#11 private key object label.
	ObjectLabel string
	// SocketDir is the directory under which the Unix socket is created.
	SocketDir string
	// EngineDynamicPath is the full path to the OpenSSL pkcs11 engine shared object.
	EngineDynamicPath string
	// ModulePath is the full path to the p11-kit client module shared object.
	ModulePath string
}

// Proxy represents a running p11proxy helper instance.
// Use Stop() to cleanup resources.
type Proxy struct {
	info    Info
	tmpDir  string
	sock    string
	ln      net.Listener
	stopped bool
	mu      sync.Mutex
}

var (
	infoMu      sync.RWMutex
	currentInfo Info
)

func setCurrentInfo(info Info) {
	infoMu.Lock()
	defer infoMu.Unlock()
	currentInfo = info
}

// SetCurrentInfoForTest allows unit tests to override the globally cached PKCS#11 helper info.
func SetCurrentInfoForTest(info Info) {
	setCurrentInfo(info)
}

// CurrentInfo returns the latest PKCS#11 helper information recorded during Start().
func CurrentInfo() Info {
	infoMu.RLock()
	defer infoMu.RUnlock()
	return currentInfo
}

func (p *Proxy) Info() Info { return p.info }

// Log whichever failure happened first and still keep trying the others
func captureFirstError(dst *error, err error) {
	if err == nil {
		return
	}
	if *dst == nil {
		*dst = err
	}
}

// Stop removes the Unix socket (if present) and temp files.
// It is safe to call multiple times.
func (p *Proxy) Stop() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	// Already stopped, return immediately
	if p.stopped {
		return nil
	}
	p.stopped = true

	var firstErr error
	// Close the listener
	if p.ln != nil {
		_ = p.ln.Close()
	}
	// Remove the socket file
	if p.sock != "" {
		if err := os.Remove(p.sock); err != nil && !os.IsNotExist(err) {
			captureFirstError(&firstErr, err)
			log.Warnf("p11proxy: failed to remove socket %s: %v", p.sock, err)
		}
	}
	// Remove the temporary directory
	if p.tmpDir != "" {
		if err := os.RemoveAll(p.tmpDir); err != nil {
			captureFirstError(&firstErr, err)
			log.Warnf("p11proxy: failed to remove temp dir %s: %v", p.tmpDir, err)
		}
	}
	infoMu.Lock()
	if currentInfo == p.info {
		currentInfo = Info{}
	}
	infoMu.Unlock()
	return firstErr
}

// Start initializes the PKCS#11 helper. It will never return a fatal error that should
// abort server startup: on missing dependencies or unsupported environment, it logs a
// warning and returns a disabled Info.
func Start(ctx context.Context, opts Options, modules server_structs.ServerType) (*Proxy, error) {
	// If globally disabled via config, short-circuit.
	if !param.Server_EnablePKCS11.GetBool() {
		disabled := Info{Enabled: false}
		setCurrentInfo(disabled)
		return &Proxy{info: disabled}, nil
	}

	// Load server private key and cert chain paths.
	keyPath := param.Server_TLSKey.GetString()
	if keyPath == "" {
		disabled := Info{Enabled: false}
		setCurrentInfo(disabled)
		return &Proxy{info: disabled}, nil
	}
	pk, err := config.LoadPrivateKey(keyPath, true)
	if err != nil {
		log.Warnf("PKCS#11 helper disabled: failed to parse TLS key at %s: %v", keyPath, err)
		disabled := Info{Enabled: false}
		setCurrentInfo(disabled)
		return &Proxy{info: disabled}, nil
	}
	var signer crypto.Signer
	switch k := pk.(type) {
	case *ecdsa.PrivateKey:
		signer = k
	case *rsa.PrivateKey:
		signer = k
	default:
		log.Warnf("PKCS#11 helper disabled: unsupported private key type %T", pk)
		disabled := Info{Enabled: false}
		setCurrentInfo(disabled)
		return &Proxy{info: disabled}, nil
	}

	certChainPath := param.Server_TLSCertificateChain.GetString()
	if certChainPath == "" {
		log.Warn("PKCS#11 helper disabled: missing Server.TLSCertificateChain")
		disabled := Info{Enabled: false}
		setCurrentInfo(disabled)
		return &Proxy{info: disabled}, nil
	}

	// Prepare temp workspace.
	tmpDir, err := os.MkdirTemp("", "pelican-p11proxy-*")
	if err != nil {
		log.Warnf("PKCS#11 helper disabled: cannot create temp dir: %v", err)
		disabled := Info{Enabled: false}
		setCurrentInfo(disabled)
		return &Proxy{info: disabled}, nil
	}

	proxy := &Proxy{tmpDir: tmpDir}

	// Determine engine/module paths.
	enginePath := opts.EngineDynamicPath
	if enginePath == "" {
		enginePath = autoDetectEngine()
	}
	modulePath := opts.ModulePath
	if modulePath == "" {
		modulePath = autoDetectP11KitClient()
	}
	missing := make([]string, 0, 2)
	if enginePath == "" {
		missing = append(missing, "pkcs11 engine (libengine-pkcs11-openssl)")
	}
	if modulePath == "" {
		missing = append(missing, "p11-kit client (p11-kit-client.so)")
	}
	if len(missing) > 0 {
		log.Warnf("PKCS#11 helper disabled: missing %s. Install packages: openssl, p11-kit-modules, libengine-pkcs11-openssl (distro-specific)", strings.Join(missing, ", "))
		_ = proxy.Stop()
		disabled := Info{Enabled: false}
		setCurrentInfo(disabled)
		return &Proxy{info: disabled}, nil
	}

	xrootdRun := param.Origin_RunLocation.GetString()
	if modules.IsEnabled(server_structs.CacheType) {
		xrootdRun = param.Cache_RunLocation.GetString()
	}

	// Create a path for the Unix socket
	var runtimeBase string
	if xrootdRun != "" {
		runtimeBase = xrootdRun
	} else {
		runtimeBase = "/tmp"
	}
	sockDir := opts.SocketDir
	if sockDir == "" {
		sockDir = runtimeBase
	}
	if err := os.MkdirAll(sockDir, 0755); err != nil {
		log.Warnf("PKCS#11 helper disabled: cannot ensure socket directory: %v", err)
		_ = proxy.Stop()
		disabled := Info{Enabled: false}
		setCurrentInfo(disabled)
		return &Proxy{info: disabled}, nil
	}
	sockPath, err := uniqueSocketPath(sockDir)
	if err != nil {
		log.Warnf("PKCS#11 helper disabled: cannot derive socket path: %v", err)
		_ = proxy.Stop()
		disabled := Info{Enabled: false}
		setCurrentInfo(disabled)
		return &Proxy{info: disabled}, nil
	}
	proxy.sock = sockPath

	// Generate OpenSSL engine config.
	opensslConf := filepath.Join(tmpDir, "openssl-pkcs11.cnf")
	if err := writeOpenSSLConf(opensslConf, enginePath, modulePath); err != nil {
		log.Warnf("PKCS#11 helper disabled: cannot write OpenSSL config: %v", err)
		_ = proxy.Stop()
		disabled := Info{Enabled: false}
		setCurrentInfo(disabled)
		return &Proxy{info: disabled}, nil
	}

	// Build PKCS#11 URL.
	token := opts.TokenLabel
	if token == "" {
		token = "pelican-tls"
	}
	object := opts.ObjectLabel
	if object == "" {
		object = "server-key"
	}
	pkcs11URL := fmt.Sprintf("pkcs11:token=%s;object=%s;type=private", escapePKCS11(token), escapePKCS11(object))

	// Load first certificate from the chain for association with the private key.
	leafCert, err := config.LoadCertificate(certChainPath)
	if err != nil {
		log.Warnf("PKCS#11 helper disabled: cannot parse certificate chain: %v", err)
		_ = proxy.Stop()
		disabled := Info{Enabled: false}
		setCurrentInfo(disabled)
		return &Proxy{info: disabled}, nil
	}

	// Start p11-kit RPC server with the signer and cert.
	enabled, ln, err := startServer(ctx, signer, leafCert, sockPath, token, object)
	if err != nil {
		log.Warnf("PKCS#11 helper disabled: cannot start p11-kit RPC server: %v", err)
	}
	if !enabled {
		_ = proxy.Stop()
		disabled := Info{Enabled: false}
		setCurrentInfo(disabled)
		return &Proxy{info: disabled}, nil
	}
	proxy.ln = ln
	proxy.info = Info{
		Enabled:         true,
		ServerAddress:   "unix:path=" + sockPath,
		PKCS11URL:       pkcs11URL,
		OpenSSLConfPath: opensslConf,
		CertPath:        certChainPath,
		ModulePath:      modulePath,
	}
	setCurrentInfo(proxy.info)

	// Ensure we remove the socket file on context cancellation.
	go func(sock string) {
		<-ctx.Done()
		_ = proxy.Stop()
	}(sockPath)

	return proxy, nil
}

func uniqueSocketPath(sockDir string) (string, error) {
	randBytes := make([]byte, 6)
	if _, err := rand.Read(randBytes); err != nil {
		return "", err
	}
	name := fmt.Sprintf("pelican-p11-%d-%s.sock", os.Getpid(), hex.EncodeToString(randBytes))
	return filepath.Join(sockDir, name), nil
}

func writeOpenSSLConf(path, enginePath, modulePath string) error {
	content := strings.Builder{}
	content.WriteString("openssl_conf = openssl_init\n\n")
	content.WriteString("[openssl_init]\n")
	content.WriteString("engines = engine_section\n\n")
	content.WriteString("[engine_section]\n")
	content.WriteString("pkcs11 = pkcs11_section\n\n")
	content.WriteString("[pkcs11_section]\n")
	content.WriteString("engine_id = pkcs11\n")
	content.WriteString("dynamic_path = ")
	content.WriteString(enginePath)
	content.WriteString("\n")
	content.WriteString("MODULE_PATH = ")
	content.WriteString(modulePath)
	content.WriteString("\n")
	content.WriteString("init = 0\n")
	return os.WriteFile(path, []byte(content.String()), 0644)
}

func autoDetectEngine() string {
	candidates := []string{
		"/usr/lib/x86_64-linux-gnu/engines-3/pkcs11.so",
		"/usr/lib64/engines-3/pkcs11.so",
		"/usr/lib/ssl/engines-3/pkcs11.so",
		"/usr/lib/x86_64-linux-gnu/engines-1.1/pkcs11.so",
	}
	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p
		}
	}
	return ""
}

func autoDetectP11KitClient() string {
	candidates := []string{
		"/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so",
		"/usr/lib64/pkcs11/p11-kit-client.so",
		"/usr/lib/pkcs11/p11-kit-client.so",
		"/usr/lib/p11-kit-client.so",
	}
	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p
		}
	}
	return ""
}

func escapePKCS11(s string) string {
	// Per RFC 7512 section 2.3, special characters must be percent-encoded.
	replacer := strings.NewReplacer("%", "%25", ";", "%3B", "=", "%3D", ":", "%3A", ",", "%2C", " ", "%20")
	return replacer.Replace(s)
}

// startServer starts the p11-kit RPC server and binds the provided signer and certificate
// to the given token/object labels.
func startServer(ctx context.Context, signer crypto.Signer, cert *x509.Certificate, sockPath, tokenLabel, objectLabel string) (bool, net.Listener, error) {
	// Build objects
	privObj, err := p11kit.NewPrivateKeyObject(signer)
	if err != nil {
		return false, nil, errors.Wrap(err, "error in creating private key object")
	}
	privObj.SetLabel(objectLabel)
	privObj.SetID(1)
	if cert != nil {
		err = privObj.SetCertificate(cert)
		if err != nil {
			return false, nil, errors.Wrap(err, "error in setting certificate")
		}
	}

	objs := []p11kit.Object{privObj}
	if cert != nil {
		certObj, err := p11kit.NewX509CertificateObject(cert)
		if err == nil {
			certObj.SetLabel("server-cert")
			certObj.SetID(2)
			objs = append(objs, certObj)
		}
	}

	slot := p11kit.Slot{
		ID:              0x01,
		Description:     "Pelican p11 proxy",
		Label:           tokenLabel,
		Manufacturer:    "Pelican",
		Model:           "p11proxy",
		Serial:          "0001",
		HardwareVersion: p11kit.Version{Major: 0, Minor: 1},
		FirmwareVersion: p11kit.Version{Major: 0, Minor: 1},
		Objects:         objs,
	}

	h := p11kit.Handler{
		Manufacturer:   "Pelican",
		Library:        "pelican-p11",
		LibraryVersion: p11kit.Version{Major: 0, Minor: 1},
		Slots:          []p11kit.Slot{slot},
	}

	log.Tracef("p11proxy: removing any stale socket at %s", sockPath)
	if err := os.Remove(sockPath); err != nil && !os.IsNotExist(err) {
		return false, nil, errors.Wrapf(err, "cannot remove stale socket at %s", sockPath)
	}

	log.Tracef("p11proxy: creating Unix socket at %s", sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return false, nil, errors.Wrapf(err, "cannot bind unix socket at %s", sockPath)
	}
	log.Tracef("p11proxy: Unix socket created successfully")

	// Verify socket exists immediately after creation
	if _, err := os.Stat(sockPath); err != nil {
		log.Errorf("p11proxy: CRITICAL - socket file doesn't exist right after net.Listen: %v", err)
		return false, nil, errors.Wrapf(err, "socket file doesn't exist after creation at %s", sockPath)
	}
	log.Tracef("p11proxy: verified socket file exists at %s", sockPath)

	// Ensure socket has appropriate perms and group
	gid, err := config.GetDaemonGID()
	if err != nil {
		return false, nil, errors.Wrap(err, "error in getting XRootD User's GID")
	}
	log.Tracef("p11proxy: setting socket permissions to 0660 and gid to %d", gid)

	if err := os.Chmod(sockPath, 0660); err != nil {
		log.Warnf("p11proxy: failed to chmod socket %s to 0660: %v", sockPath, err)
	} else {
		log.Tracef("p11proxy: chmod successful")
	}

	if err := os.Chown(sockPath, -1, gid); err != nil {
		log.Warnf("p11proxy: failed to chown socket %s to gid %d: %v", sockPath, gid, err)
	} else {
		log.Tracef("p11proxy: chown successful")
	}

	// Final verification
	if fi, err := os.Stat(sockPath); err != nil {
		log.Errorf("p11proxy: CRITICAL - socket disappeared after chmod/chown: %v", err)
	} else {
		log.Tracef("p11proxy: final socket state: mode=%v size=%d", fi.Mode(), fi.Size())
	}

	// Serve loop
	go func() {
		log.Tracef("p11proxy: RPC server started, waiting for connections on %s", sockPath)
		for {
			conn, err := ln.Accept()
			if err != nil {
				// Likely listener closed
				log.Tracef("p11proxy: accept error (listener likely closed): %v", err)
				return
			}
			log.Tracef("p11proxy: accepted connection from remote=%v local=%v", conn.RemoteAddr(), conn.LocalAddr())
			go func(c net.Conn) {
				defer func() {
					log.Tracef("p11proxy: closing connection from %v", c.RemoteAddr())
					c.Close()
				}()
				log.Infof("p11proxy: calling handler for connection from %v", c.RemoteAddr())
				if err := h.Handle(c); err != nil {
					// EOF errors during shutdown are expected, log at trace level
					errMsg := err.Error()
					// p11-kit library wraps the EOF error differently, preventing errors.Is() from detecting it
					if strings.Contains(errMsg, "EOF") {
						log.Tracef("p11proxy: connection closed: %v", err)
					} else {
						log.Warnf("p11proxy: handler error: %v", err)
					}
				} else {
					log.Tracef("p11proxy: handler completed successfully for %v", c.RemoteAddr())
				}
			}(conn)
		}
	}()

	// Cancel handler: close listener when context is done
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	return true, ln, nil
}
