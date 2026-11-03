// Command tools runs the load-test environment's helpers:
//
//	tools upstream   mock upstream: ?latency=10ms&status=503, /sse streams
//	tools idp        mock IdP over TLS with its own CA: /jwks.json, /token?sub=
//	tools seed       first user, test policy published, edge token file
//	tools bootstrap  write a bootstrap snapshot of the test policy to $SHARED
//	tools probe URL  wait until URL answers 200, for the image smoke
//	tools lb         mock load balancer with health checks (flags: -backends)
//	tools gateway    mock gateway behind the edge, routing by path (flags: -routes)
//	tools streams    hold SSE and WebSocket connections (flags: -sse -ws -for)
//	tools service X  mock microservice X for the capacity test: catalog, orders, account, content
//	tools agent      scripted autopilot runner for the load-full attacks (flags: -admin -token-file -plan -concurrency)
//
// Configuration comes from the environment, as in compose.yaml.
package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chrisleekr/edge-proxy/internal/admin"
	"github.com/chrisleekr/edge-proxy/internal/snapshot"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: tools upstream|idp|seed|bootstrap|probe|lb|gateway|streams|service|agent")
	}
	var err error
	switch os.Args[1] {
	case "upstream":
		srv := &http.Server{Addr: ":8080", Handler: http.HandlerFunc(upstream), ReadHeaderTimeout: 5 * time.Second}
		err = srv.ListenAndServe()
	case "idp":
		err = idp()
	case "seed":
		err = seed(context.Background())
	case "bootstrap":
		err = bootstrap()
	case "probe":
		err = probe(os.Args[2:])
	case "lb":
		err = lb(os.Args[2:])
	case "gateway":
		err = gateway(os.Args[2:])
	case "streams":
		err = streams(os.Args[2:])
	case "service":
		err = service(os.Args[2:])
	case "agent":
		err = agent(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		log.Fatal(err)
	}
}

// upstream answers like a small API. The response echoes what the edge
// forwarded (auth subject, locale, the canary marker header), so k6 can
// check those end to end.
func upstream(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if d, err := time.ParseDuration(q.Get("latency")); err == nil {
		time.Sleep(d)
	}
	if r.URL.Path == "/ws" {
		wsEcho(w, r)
		return
	}
	if r.URL.Path == "/sse" {
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 0; r.Context().Err() == nil; i++ {
			_, _ = fmt.Fprintf(w, "data: %d\n\n", i)
			w.(http.Flusher).Flush()
			time.Sleep(time.Second)
		}
		return
	}
	status, _ := strconv.Atoi(q.Get("status"))
	if status == 0 {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"sub": r.Header.Get("X-Edge-Auth-Sub"), "issuer": r.Header.Get("X-Edge-Auth-Issuer"),
		"locale": r.Header.Get("X-Edge-Locale"), "canary": r.Header.Get("X-Canary")})
}

// idp writes a CA certificate to $SHARED/ca.pem, which admin and the edges
// trust through SSL_CERT_FILE, and serves an ES256 JWKS and tokens.
func idp() error {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "loadtest CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(30 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"idp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	pemCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if err := writeShared("ca.pem", pemCA); err != nil {
		return err
	}

	signer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b := func(n *big.Int) string { return base64.RawURLEncoding.EncodeToString(n.FillBytes(make([]byte, 32))) }
	jwks, _ := json.Marshal(map[string]any{"keys": []map[string]string{{"kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "use": "sig",
		"x": b(signer.X), "y": b(signer.Y)}}})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /jwks.json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(jwks) })
	mux.HandleFunc("GET /token", func(w http.ResponseWriter, r *http.Request) {
		// iss and aud default to the main issuer; the demo also signs for its
		// partner issuer, which shares this JWKS.
		q := r.URL.Query()
		iss, aud := cmp.Or(q.Get("iss"), "https://idp"), cmp.Or(q.Get("aud"), "loadtest")
		t := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"iss": iss, "aud": aud, "sub": q.Get("sub"),
			"exp": time.Now().Add(time.Hour).Unix()})
		t.Header["kid"] = "k1"
		s, err := t.SignedString(signer)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		_, _ = io.WriteString(w, s)
	})
	srv := &http.Server{Addr: ":8443", Handler: mux, ReadHeaderTimeout: 5 * time.Second, TLSConfig: &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}, MinVersion: tls.VersionTLS12}}
	return srv.ListenAndServeTLS("", "")
}

// nonroot is the distroless nonroot user that admin and the edges run as.
const nonroot = 65532

// writeShared writes a file only the services' user can read.
func writeShared(name string, b []byte) error {
	path := filepath.Join(os.Getenv("SHARED"), name)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return err
	}
	return os.Chown(path, nonroot, nonroot)
}

// bootstrap writes the snapshot an edge loads with no admin, as an export
// would.
func bootstrap() error {
	var p struct {
		Config snapshot.Config `json:"config"`
	}
	if err := json.Unmarshal(policy, &p); err != nil {
		return err
	}
	p.Config.Version = 1
	b, err := json.Marshal(snapshot.Envelope{ExportedAt: time.Now().UTC(), Active: &p.Config, FleetSize: 1})
	if err != nil {
		return err
	}
	return writeShared("bootstrap.json", b)
}

// waitClient polls services coming up; a timeout so one accepted but
// unanswered request doesn't stall the wait loop.
var waitClient = &http.Client{Timeout: 2 * time.Second}

func probe(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: tools probe URL")
	}
	for range 30 {
		if resp, err := waitClient.Get(args[0]); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("%s never answered 200", args[0])
}

//go:embed policy.json
var policy []byte

// demoPolicy is the demo's richer policy: one example of each feature.
//
//go:embed demo-policy.json
var demoPolicy []byte

// seed creates the first admin the way the CLI does, then uses the API as
// an operator would: save the test policy, publish it, create an edge token.
func seed(ctx context.Context) error {
	// The token is written last, so its presence means a previous run
	// finished; compose up on an existing stack must not fail here.
	if _, err := os.Stat(filepath.Join(os.Getenv("SHARED"), "edge-token")); err == nil {
		log.Print("already seeded")
		return nil
	}
	cfg, err := admin.LoadConfig(os.Getenv)
	if err != nil {
		return err
	}
	db, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()
	// Local demo only. Admin requires at least 15 characters, and neither the
	// username nor the service name inside the password.
	const user, password = "admin", "local-dev-login" //nolint:gosec // the published demo login, not a secret
	if _, err := admin.CreateUser(ctx, db, cfg, time.Now, "cli", user, "", password, []string{"admin"}); err != nil {
		return fmt.Errorf("create user: %w", err)
	}

	base := os.Getenv("ADMIN_API")
	for i := 0; ; i++ {
		if resp, err := waitClient.Get(base + "/api/auth/me"); err == nil {
			_ = resp.Body.Close()
			break
		}
		if i == 60 {
			return errors.New("admin did not start")
		}
		time.Sleep(time.Second)
	}
	var cookie string
	call := func(method, path string, body any, want int, hdr ...string) ([]byte, error) {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		// The session cookie is Secure; over this plain internal hop the
		// client must send it explicitly.
		if cookie != "" {
			req.Header.Set("Cookie", cookie)
		}
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		out, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			return nil, fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, out)
		}
		if c := resp.Cookies(); len(c) > 0 {
			cookie = c[0].Name + "=" + c[0].Value
		}
		return out, nil
	}
	if _, err := call("POST", "/api/auth/login", map[string]string{"username": user, "password": password}, 200); err != nil {
		return err
	}
	var p struct {
		Config json.RawMessage `json:"config"`
		Tests  json.RawMessage `json:"tests"`
	}
	// SEED_POLICY=demo seeds the demo's policy; load tests assert on the
	// smaller default one.
	src, msg := policy, "load test policy"
	if os.Getenv("SEED_POLICY") == "demo" {
		src, msg = demoPolicy, "demo policy: one example of each feature"
	}
	if err := json.Unmarshal(src, &p); err != nil {
		return err
	}
	if _, err := call("PUT", "/api/draft", p, 200, "If-Match", `"0"`); err != nil {
		return err
	}
	if _, err := call("POST", "/api/publish", map[string]string{"message": msg}, 201, "If-Match", `"1"`); err != nil {
		return err
	}
	out, err := call("POST", "/api/tokens", map[string]string{"name": "edges", "kind": "edge"}, 201)
	if err != nil {
		return err
	}
	var tok struct{ Token string }
	_ = json.Unmarshal(out, &tok)
	log.Print("seeded: policy published, edge token written")
	return writeShared("edge-token", []byte(tok.Token+"\n"))
}
