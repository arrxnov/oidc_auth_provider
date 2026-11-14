package oidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/MythicMeta/MythicContainer/mythicrpc"
	"github.com/MythicMeta/MythicContainer/rabbitmq"
	"golang.org/x/oauth2"
)

// Operators upload these three files in the Mythic UI (Files -> Uploads) using
// EXACTLY these names. Nothing is mounted and config.json is untouched.
// Any subset that is absent simply isn't used:
//   - none present            -> feature off, behaviour identical to before
//   - CA only                 -> custom trust, no client cert
//   - cert + key (+/- CA)     -> mTLS
const (
	mtlsCertFilename = "oidc_mtls_client.pem"
	mtlsKeyFilename  = "oidc_mtls_client.key"
	mtlsCAFilename   = "oidc_mtls_ca.pem"

	// How often a login re-checks Mythic's file store. Re-uploading a file
	// creates a NEW file UUID, so rotation = upload again, picked up within
	// this window with no container restart.
	mtlsRefreshEvery = 60 * time.Second
)

var (
	mtlsMu      sync.Mutex
	mtlsOpID    int          // operation whose file store we search
	mtlsChecked time.Time    // last successful file-store check
	mtlsFileIDs [3]string    // agent_file_ids the cached client was built from (cert, key, CA)
	mtlsClient  *http.Client // cached; nil when feature is off
	mtlsExpires time.Time    // client cert NotAfter (zero if no client cert)
)

// setScopeOperation records the operation ID Mythic reports at container
// start. Auth logins happen before any task/callback exists, so there is no
// task or callback to scope a file search with; the operation is the only
// scope available here.
func setScopeOperation(id int) {
	mtlsMu.Lock()
	defer mtlsMu.Unlock()
	mtlsOpID = id
	mtlsChecked = time.Time{} // force a fresh lookup on next login
	log.Printf("oidc mTLS: searching operation %d's files for %s / %s / %s",
		id, mtlsCertFilename, mtlsKeyFilename, mtlsCAFilename)
}

// fileSearchMessage mirrors mythicrpc.MythicRPCFileSearchMessage but adds the
// operation_id field understood by Mythic. The pinned MythicContainer release
// does not expose OperationID on its search message, so send the RPC directly.
type fileSearchMessage struct {
	mythicrpc.MythicRPCFileSearchMessage
	OperationID int `json:"operation_id"`
}

func sendFileSearch(opID int, name string) (*mythicrpc.MythicRPCFileSearchMessageResponse, error) {
	responseBytes, err := rabbitmq.RabbitMQConnection.SendRPCStructMessage(
		rabbitmq.MYTHIC_EXCHANGE,
		rabbitmq.MYTHIC_RPC_FILE_SEARCH,
		fileSearchMessage{
			MythicRPCFileSearchMessage: mythicrpc.MythicRPCFileSearchMessage{
				Filename:   name,
				MaxResults: 5,
			},
			OperationID: opID,
		},
	)
	if err != nil {
		return nil, err
	}

	var response mythicrpc.MythicRPCFileSearchMessageResponse
	if err := json.Unmarshal(responseBytes, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// findFile returns the agent_file_id of the newest COMPLETE upload with this
// exact filename, or "" if none exists. Deleted files aren't returned by
// Mythic's search, so deleting in the UI == removing the setting.
func findFile(opID int, name string) (string, error) {
	resp, err := sendFileSearch(opID, name)
	if err != nil {
		return "", err
	}
	if !resp.Success {
		return "", errors.New(resp.Error)
	}

	var best mythicrpc.FileData
	for _, f := range resp.Files {
		// Exact name match only (search may be fuzzy) and only fully-uploaded
		// files, so a half-finished chunked upload is never parsed.
		if f.Filename != name || !f.Complete {
			continue
		}
		// Several uploads can share a name (re-uploads); newest wins.
		if best.AgentFileID == "" || f.Timestamp.After(best.Timestamp) {
			best = f
		}
	}
	return best.AgentFileID, nil
}

// fetchFile reads a file's bytes from Mythic by its UUID. AgentFileID alone is
// enough to identify the file, so no operation scoping is needed here.
func fetchFile(id string) ([]byte, error) {
	resp, err := mythicrpc.SendMythicRPCFileGetContent(mythicrpc.MythicRPCFileGetContentMessage{
		AgentFileID: id,
	})
	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, errors.New(resp.Error)
	}
	return resp.Content, nil
}

// buildClient assembles the HTTP client from PEM bytes held in memory (the
// key never touches this container's disk). Returns the cert's NotAfter.
func buildClient(certPEM, keyPEM, caPEM []byte) (*http.Client, time.Time, error) {
	// Half a keypair is always a mistake; refuse rather than silently
	// connecting without client auth.
	if (len(certPEM) == 0) != (len(keyPEM) == 0) {
		return nil, time.Time{}, fmt.Errorf("upload both %s and %s (only one found)", mtlsCertFilename, mtlsKeyFilename)
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12} // no InsecureSkipVerify, by design

	if len(caPEM) > 0 {
		// CA present => trust ONLY it (pins trust to your PKI). If you also
		// need public roots, append them to the uploaded bundle.
		pool := x509.NewCertPool()
		// false means zero certs parsed; otherwise we'd get an empty pool and
		// a misleading "unknown authority" on every login.
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, time.Time{}, fmt.Errorf("no valid PEM certificates in %s", mtlsCAFilename)
		}
		tlsCfg.RootCAs = pool
	}

	var notAfter time.Time
	if len(certPEM) > 0 {
		pair, err := tls.X509KeyPair(certPEM, keyPEM) // also verifies key matches cert
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("client cert/key: %w", err)
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("parse client cert: %w", err)
		}
		now := time.Now()
		if now.After(leaf.NotAfter) {
			return nil, time.Time{}, fmt.Errorf("client cert expired %s", leaf.NotAfter)
		}
		if now.Before(leaf.NotBefore) {
			return nil, time.Time{}, fmt.Errorf("client cert not valid until %s (clock skew?)", leaf.NotBefore)
		}
		if time.Until(leaf.NotAfter) < 14*24*time.Hour {
			log.Printf("oidc mTLS: client cert expires soon (%s)", leaf.NotAfter)
		}
		tlsCfg.Certificates = []tls.Certificate{pair}
		notAfter = leaf.NotAfter
	}

	// Clone the default transport to keep proxy env vars, keepalives, etc.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}, notAfter, nil
}

// clientIfValid must be called with mtlsMu held.
func clientIfValid() (*http.Client, error) {
	// The cert can expire between refreshes while its file UUID is unchanged.
	if mtlsClient != nil && !mtlsExpires.IsZero() && time.Now().After(mtlsExpires) {
		return nil, fmt.Errorf("client cert expired %s; upload a new %s and %s",
			mtlsExpires, mtlsCertFilename, mtlsKeyFilename)
	}
	return mtlsClient, nil
}

// idpClient returns the cached mTLS client, refreshing from Mythic's file
// store at most once per mtlsRefreshEvery. (nil, nil) means feature off.
func idpClient() (*http.Client, error) {
	mtlsMu.Lock()
	defer mtlsMu.Unlock() // held across RPCs on purpose: avoids duplicate fetches under concurrent logins

	if mtlsOpID == 0 {
		return nil, nil // no scope available: behave as before
	}
	if !mtlsChecked.IsZero() && time.Since(mtlsChecked) < mtlsRefreshEvery {
		return clientIfValid()
	}

	// Transient RPC trouble (Mythic restarting, RabbitMQ blip) must not
	// silently downgrade to default trust, so keep the last good client; with
	// no prior client, fail the login instead.
	fallback := func(err error) (*http.Client, error) {
		if mtlsClient != nil {
			log.Printf("oidc mTLS: refresh failed (%v); using previous client", err)
			return clientIfValid()
		}
		return nil, fmt.Errorf("oidc mTLS: %w", err)
	}

	var ids [3]string
	for i, name := range []string{mtlsCertFilename, mtlsKeyFilename, mtlsCAFilename} {
		id, err := findFile(mtlsOpID, name)
		if err != nil {
			return fallback(err)
		}
		ids[i] = id
	}
	mtlsChecked = time.Now()

	if ids == mtlsFileIDs {
		return clientIfValid() // nothing changed (includes "still nothing uploaded")
	}

	// Files changed (uploaded, re-uploaded, or deleted): rebuild.
	var contents [3][]byte
	for i, id := range ids {
		if id == "" {
			continue
		}
		b, err := fetchFile(id)
		if err != nil {
			return fallback(err)
		}
		contents[i] = b
	}

	var (
		c        *http.Client
		notAfter time.Time
	)
	if ids != [3]string{} {
		var err error
		if c, notAfter, err = buildClient(contents[0], contents[1], contents[2]); err != nil {
			// Bad upload: keep serving the previous good client and don't
			// record these IDs, so the next refresh retries.
			return fallback(err)
		}
	} // else: everything was deleted => feature off (c stays nil)

	if mtlsClient != nil {
		if t, ok := mtlsClient.Transport.(*http.Transport); ok {
			t.CloseIdleConnections() // don't leak pooled conns bound to the old cert/CA
		}
	}
	mtlsClient, mtlsExpires, mtlsFileIDs = c, notAfter, ids
	log.Printf("oidc mTLS: reloaded (client cert: %t, custom CA: %t)", ids[0] != "", ids[2] != "")
	return mtlsClient, nil
}

// withIdPClient attaches the client to ctx (no-op when feature is off).
// oauth2.Config.Exchange and go-oidc's NewProvider both read the client from
// the oauth2.HTTPClient context key. Safe to apply more than once.
func withIdPClient(ctx context.Context) (context.Context, error) {
	c, err := idpClient()
	if err != nil || c == nil {
		return ctx, err
	}
	return context.WithValue(ctx, oauth2.HTTPClient, c), nil
}
