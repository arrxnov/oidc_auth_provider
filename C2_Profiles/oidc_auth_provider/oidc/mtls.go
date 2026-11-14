package oidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/oauth2"
)

// readMTLSFile reads a file from the same runtime directory exposed by the
// auth container's file browser (the directory containing the executable and
// config.json). Only plain filenames are accepted; use the file browser's
// Upload button to add them.
func readMTLSFile(name string) ([]byte, error) {
	if name == "" {
		return nil, nil
	}
	if filepath.Base(name) != name || name == "." || name == ".." {
		return nil, fmt.Errorf("mTLS filename %q must be a plain filename in the container directory", name)
	}

	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("locate container directory: %w", err)
	}
	path := filepath.Join(filepath.Dir(exe), name)
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read mTLS file %q: %w", name, err)
	}
	return contents, nil
}

// buildClient assembles the HTTP client from PEM bytes read from the
// container's runtime directory (the key never leaves this container).
func buildClient(certPEM, keyPEM, caPEM []byte) (*http.Client, error) {
	// Half a keypair is always a mistake; refuse rather than silently
	// connecting without client auth.
	if (len(certPEM) == 0) != (len(keyPEM) == 0) {
		return nil, fmt.Errorf("configure both mtls_cert_file and mtls_key_file (only one is set)")
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12} // no InsecureSkipVerify, by design

	if len(caPEM) > 0 {
		// CA present => trust ONLY it (pins trust to your PKI). If you also
		// need public roots, append them to the uploaded bundle.
		pool := x509.NewCertPool()
		// false means zero certs parsed; otherwise we'd get an empty pool and
		// a misleading "unknown authority" on every login.
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("no valid PEM certificates in mtls_ca_file")
		}
		tlsCfg.RootCAs = pool
	}

	if len(certPEM) > 0 {
		pair, err := tls.X509KeyPair(certPEM, keyPEM) // also verifies key matches cert
		if err != nil {
			return nil, fmt.Errorf("client cert/key: %w", err)
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parse client cert: %w", err)
		}
		now := time.Now()
		if now.After(leaf.NotAfter) {
			return nil, fmt.Errorf("client cert expired %s", leaf.NotAfter)
		}
		if now.Before(leaf.NotBefore) {
			return nil, fmt.Errorf("client cert not valid until %s (clock skew?)", leaf.NotBefore)
		}
		if time.Until(leaf.NotAfter) < 14*24*time.Hour {
			log.Printf("oidc mTLS: client cert expires soon (%s)", leaf.NotAfter)
		}
		tlsCfg.Certificates = []tls.Certificate{pair}
	}

	// Clone the default transport to keep proxy env vars, keepalives, etc.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}, nil
}

// idpClient returns an HTTP client built from the files named in config.json.
// (nil, nil) means no mTLS files are configured, so behaviour is unchanged.
// Files are read on each login so uploads and rotations take effect without a
// container restart.
func idpClient(config *Config) (*http.Client, error) {
	certPEM, err := readMTLSFile(config.MTLSCertFile)
	if err != nil {
		return nil, err
	}
	keyPEM, err := readMTLSFile(config.MTLSKeyFile)
	if err != nil {
		return nil, err
	}
	caPEM, err := readMTLSFile(config.MTLSCAFile)
	if err != nil {
		return nil, err
	}

	if len(certPEM) == 0 && len(keyPEM) == 0 && len(caPEM) == 0 {
		return nil, nil
	}
	return buildClient(certPEM, keyPEM, caPEM)
}

// withIdPClient attaches the client to ctx (no-op when no mTLS files are
// configured). oauth2.Config.Exchange and go-oidc's NewProvider both read the
// client from the oauth2.HTTPClient context key. Safe to apply more than once.
func withIdPClient(ctx context.Context, config *Config) (context.Context, error) {
	c, err := idpClient(config)
	if err != nil || c == nil {
		return ctx, err
	}
	return context.WithValue(ctx, oauth2.HTTPClient, c), nil
}
