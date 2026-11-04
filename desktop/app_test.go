package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fixtureLink = "vless://11111111-1111-4111-8111-111111111111@original.example:443?encryption=none&security=tls&sni=localhost&type=ws&host=localhost&path=%2Ffixture#US"

func TestCandidates(t *testing.T) {
	eps, e := parseCandidates("8.8.8.8:8443\n8.8.8.8:8443\n1.1.1.0/30", 443)
	if e != nil || len(eps) != 3 || eps[0].Port != 8443 {
		t.Fatalf("%v %v", eps, e)
	}
	for _, s := range []string{"127.0.0.1", "10.0.0.0/24", "8.0.0.0/8", "8.8.8.8:0", "::1", "8.8.8.8:65536"} {
		if _, e := parseCandidates(s, 443); e == nil {
			t.Fatal(s)
		}
	}
}
func TestTemplateConfigAndExport(t *testing.T) {
	ep := Endpoint{"8.8.8.8", 8443}
	cfg, e := buildConfig([]Template{{Link: fixtureLink}}, []work{{Endpoint: ep, Port: 12345}})
	if e != nil {
		t.Fatal(e)
	}
	outs := cfg["outbounds"].([]any)
	if outs[0].(map[string]any)["protocol"] != "blackhole" {
		t.Fatal("No safe default")
	}
	out := outs[1].(map[string]any)
	v := out["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
	if v["address"] != ep.IP || v["port"] != 8443 {
		t.Fatal(v)
	}
	stream := out["streamSettings"].(map[string]any)
	if stream["tlsSettings"].(map[string]any)["serverName"] != "localhost" || stream["wsSettings"].(map[string]any)["path"] != "/fixture" {
		t.Fatal(stream)
	}
	for _, s := range []string{strings.Replace(fixtureLink, "#US", "&unknown=1#US", 1), strings.Replace(fixtureLink, "security=tls", "security=none", 1), strings.Replace(fixtureLink, "encryption=none", "encryption=auto", 1), strings.Replace(fixtureLink, "security=tls", "security=tls&allowInsecure=1", 1)} {
		if _, e := parseTemplate(Template{Link: s}); e == nil {
			t.Fatal("Accepted unsupported template")
		}
	}
	a := testApp(t)
	a.state.Templates = []Template{{Link: fixtureLink}}
	a.state.Results["x"] = Result{Endpoint: ep, Status: "passed", Template: 0}
	res := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://127.0.0.1:1234/api/export?format=links", nil)
	req.Header.Set("X-NCV-Token", a.token)
	a.handler().ServeHTTP(res, req)
	u, e := url.Parse(strings.TrimSpace(res.Body.String()))
	if e != nil || u.Host != "8.8.8.8:8443" || u.Query().Get("sni") != "localhost" || u.Query().Get("path") != "/fixture" {
		t.Fatal(res.Body.String(), e)
	}
}
func testApp(t *testing.T) *App {
	t.Helper()
	return &App{dir: t.TempDir(), token: "test-secret", state: State{Status: "paused", Results: map[string]Result{}}}
}
func TestSaveResumeAndFallback(t *testing.T) {
	a := testApp(t)
	a.state.Name = "first"
	if e := a.save(); e != nil {
		t.Fatal(e)
	}
	a.state.Name = "second"
	a.state.Status = "running"
	a.save()
	b := &App{dir: a.dir}
	b.load()
	if b.state.Name != "second" || b.state.Status != "paused" {
		t.Fatal(b.state)
	}
	os.WriteFile(filepath.Join(a.dir, "state.json"), []byte("broken"), 0600)
	b.load()
	if b.state.Name != "first" {
		t.Fatal("No checkpoint fallback")
	}
}
func TestLoopbackAuthAndOrigin(t *testing.T) {
	a := testApp(t)
	for _, tc := range []struct {
		host, token, origin string
		status              int
	}{{"127.0.0.1:1234", "", "", 401}, {"evil.example:1234", a.token, "", 403}, {"127.0.0.1:1234", a.token, "https://evil.example", 403}, {"127.0.0.1:1234", a.token, "http://127.0.0.1:1234", 200}} {
		req := httptest.NewRequest("GET", "http://"+tc.host+"/api/state", nil)
		req.Header.Set("X-NCV-Token", tc.token)
		req.Header.Set("Origin", tc.origin)
		w := httptest.NewRecorder()
		a.handler().ServeHTTP(w, req)
		if w.Code != tc.status {
			t.Fatalf("%v: %d", tc, w.Code)
		}
	}
}
func TestNCVPayloadHasOnlyEndpoints(t *testing.T) {
	a := testApp(t)
	ep := Endpoint{"8.8.8.8", 8443}
	a.state.Results["pass"] = Result{Endpoint: ep, Status: "passed"}
	a.state.Results["other-template"] = Result{Endpoint: ep, Status: "passed"}
	a.state.Results["fail"] = Result{Endpoint: Endpoint{"1.1.1.1", 443}, Status: "failed"}
	received := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "admin" || p != "session-password" {
			t.Error("auth")
		}
		raw, _ := io.ReadAll(r.Body)
		if strings.Contains(string(raw), "vless") || strings.Contains(string(raw), "password") {
			t.Error("credential leak")
		}
		var data struct {
			ID        string     `json:"id"`
			Endpoints []Endpoint `json:"endpoints"`
		}
		json.Unmarshal(raw, &data)
		received += len(data.Endpoints)
		reply(w, map[string]any{"added": 1, "matched": data.Endpoints})
	}))
	defer s.Close()
	a.state.Site = s.URL
	a.state.Job = "fixture-job"
	out, e := a.ncv(s.URL, "admin", "session-password", "push", "fixture-job")
	if e != nil || received != 1 {
		t.Fatal(out, e, received)
	}
	if _, e = a.ncv(s.URL, "admin", "session-password", "push", "wrong-job"); e == nil {
		t.Fatal("Wrong task accepted")
	}
}
func TestSOCKSRemoteDNS(t *testing.T) {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	errs := make(chan error, 1)
	go func() {
		c, e := l.Accept()
		if e != nil {
			errs <- e
			return
		}
		defer c.Close()
		b := make([]byte, 3)
		io.ReadFull(c, b)
		c.Write([]byte{5, 0})
		head := make([]byte, 5)
		io.ReadFull(c, head)
		body := make([]byte, int(head[4])+2)
		io.ReadFull(c, body)
		if head[3] != 3 || string(body[:len(body)-2]) != "does-not-resolve.invalid" {
			errs <- fmt.Errorf("not remote DNS")
			return
		}
		c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 80})
		errs <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, e := socksDial(ctx, l.Addr().String(), "does-not-resolve.invalid:443")
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	if e := <-errs; e != nil {
		t.Fatal(e)
	}
}

func TestRunResumeSkipsFinishedWork(t *testing.T) {
	a := testApp(t)
	a.core = filepath.Join(a.dir, "dummy-core")
	os.WriteFile(a.core, []byte("not invoked"), 0600)
	ep := Endpoint{"127.0.0.1", 1}
	a.state.Candidates = []Endpoint{ep}
	a.state.TCPDone = []bool{true}
	a.state.TCPLatency = []float64{2}
	a.state.Templates = []Template{{Link: fixtureLink}}
	a.state.Options = Options{TCPConcurrency: 2, ProxyConcurrency: 1, Timeout: 1, Attempts: 3}
	a.state.Results[resultKey(0, ep)] = Result{Endpoint: ep, Status: "passed", Success: 3, Attempts: 3}
	if e := a.start(); e != nil {
		t.Fatal(e)
	}
	select {
	case <-a.done:
	case <-time.After(time.Second * 3):
		t.Fatal("resume hung")
	}
	if a.state.Status != "completed" || len(a.state.Results) != 1 {
		t.Fatal(a.state.Status, a.state.Error)
	}
	b := &App{dir: a.dir}
	b.load()
	if b.state.Status != "completed" || len(b.state.Results) != 1 {
		t.Fatal("lost checkpoint")
	}
}
func TestPauseSavesProgress(t *testing.T) {
	a := testApp(t)
	a.core = filepath.Join(a.dir, "dummy-core")
	os.WriteFile(a.core, []byte("not invoked"), 0600)
	for i := 0; i < 10000; i++ {
		a.state.Candidates = append(a.state.Candidates, Endpoint{"127.0.0.1", 1})
	}
	a.state.TCPDone = make([]bool, 10000)
	a.state.TCPLatency = make([]float64, 10000)
	a.state.Options = Options{TCPConcurrency: 2, ProxyConcurrency: 1, Timeout: 1, Attempts: 3}
	if e := a.start(); e != nil {
		t.Fatal(e)
	}
	a.mu.Lock()
	a.cancel()
	a.mu.Unlock()
	select {
	case <-a.done:
	case <-time.After(time.Second * 3):
		t.Fatal("pause hung")
	}
	if a.state.Status != "paused" {
		t.Fatal(a.state.Status)
	}
	b := &App{dir: a.dir}
	b.load()
	if b.state.Status != "paused" || len(b.state.Candidates) != 10000 {
		t.Fatal("pause checkpoint lost")
	}
}
