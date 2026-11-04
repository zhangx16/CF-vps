package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRealXrayWSSAndNoDirectFallback(t *testing.T) {
	core := os.Getenv("NCV_TEST_XRAY")
	if core == "" {
		t.Skip("Set NCV_TEST_XRAY for real core integration")
	}
	dir := t.TempDir()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600)
	t.Setenv("SSL_CERT_FILE", certPath)
	t.Setenv("SSL_CERT_DIR", dir)
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "socks5://127.0.0.1:1")
	t.Setenv("NO_PROXY", "*")
	var count atomic.Int32
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { count.Add(1); w.WriteHeader(204) }))
	pair, _ := tls.LoadX509KeyPair(certPath, keyPath)
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	origin.StartTLS()
	defer origin.Close()
	port := freePort(t)
	inbound := map[string]any{"log": map[string]any{"loglevel": "debug"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "vless", "settings": map[string]any{"clients": []any{map[string]any{"id": "11111111-1111-4111-8111-111111111111"}}, "decryption": "none"}, "streamSettings": map[string]any{"network": "ws", "security": "tls", "wsSettings": map[string]any{"path": "/fixture"}, "tlsSettings": map[string]any{"certificates": []any{map[string]any{"certificateFile": certPath, "keyFile": keyPath}}}}}}, "outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "network": "tcp", "ip": []string{"127.0.0.1/32"}}}}}}}
	runCore(t, core, dir, "inbound", inbound, port)
	for _, correct := range []bool{true, false} {
		link := fixtureLink
		if !correct {
			link = strings.Replace(link, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", 1)
		}
		socksPort := freePort(t)
		cfg, e := buildConfig([]Template{{Link: link}}, []work{{Endpoint: Endpoint{"127.0.0.1", port}, Port: socksPort}})
		if e != nil {
			t.Fatal(e)
		}
		out := cfg["outbounds"].([]any)[1].(map[string]any)
		out["streamSettings"].(map[string]any)["tlsSettings"].(map[string]any)["certificates"] = []any{map[string]any{"certificateFile": certPath, "usage": "verify"}}
		runCore(t, core, dir, fmt.Sprintf("client-%v", correct), cfg, socksPort)
		attempts := 3
		if !correct {
			attempts = 1
		}
		for i := 0; i < attempts; i++ {
			s := probe(context.Background(), socksPort, origin.URL, time.Second*3)
			if s.OK != correct {
				t.Fatalf("correct=%v sample=%+v", correct, s)
			}
		}
	}
	if count.Load() != 3 {
		t.Fatalf("Unexpected origin requests: %d; failed node must never fall back to direct", count.Load())
	}
}
func freePort(t *testing.T) int {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
func runCore(t *testing.T, core, dir, name string, cfg map[string]any, port int) {
	t.Helper()
	cfg["log"] = map[string]any{"loglevel": "debug"}
	raw, _ := json.Marshal(cfg)
	path := filepath.Join(dir, name+".json")
	os.WriteFile(path, raw, 0600)
	check := exec.Command(core, "run", "-test", "-c", path)
	if out, e := check.CombinedOutput(); e != nil {
		t.Fatalf("Config rejected: %s %v", out, e)
	}
	cmd := exec.Command(core, "run", "-c", path)
	logPath := filepath.Join(dir, name+".log")
	log, _ := os.Create(logPath)
	cmd.Stdout = log
	cmd.Stderr = log
	t.Cleanup(func() {
		log.Close()
		if t.Failed() {
			data, _ := os.ReadFile(logPath)
			t.Log(string(data))
		}
	})
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
		if e == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("Fixture core not ready")
}
