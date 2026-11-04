package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOnlyCFCreateAcceptsNoTCPStage(t *testing.T) {
	for _, kind := range []string{"cf-vps", "ncv"} {
		t.Run(kind, func(t *testing.T) {
			a := testApp(t)
			a.project = kind
			q := map[string]any{"name": "profile fixture", "input": "8.8.8.8:8443", "port": 443, "templates": []Template{{Link: fixtureLink}}, "site_kind": kind, "options": Options{TCPConcurrency: 0, ProxyConcurrency: 1, Timeout: 1, Attempts: 1, Target: "https://www.gstatic.com/generate_204", BypassConfirmed: true}}
			raw, _ := json.Marshal(q)
			req := httptest.NewRequest("POST", "http://127.0.0.1:1234/api/create", strings.NewReader(string(raw)))
			req.Header.Set("X-NCV-Token", a.token)
			w := httptest.NewRecorder()
			a.handler().ServeHTTP(w, req)
			if w.Code != 400 {
				t.Fatal(w.Code)
			}
			if kind == "cf-vps" {
				if len(a.state.Candidates) != 1 || a.state.Options.TCPConcurrency != 0 || !strings.Contains(w.Body.String(), "未找到") {
					t.Fatal(w.Body.String(), a.state)
				}
			} else if len(a.state.Candidates) != 0 {
				t.Fatal("NCV accepted TCP concurrency zero")
			}
		})
	}
}

func TestCFResumeIncludesCandidatesPreviouslyRejectedByTCP(t *testing.T) {
	a := testApp(t)
	a.state = State{SiteKind: "cf-vps", Status: "completed", Candidates: []Endpoint{{"8.8.8.8", 8443}}, Templates: []Template{{Link: fixtureLink}}, TCPDone: []bool{true}, TCPLatency: []float64{-1}, Results: map[string]Result{}, Options: Options{TCPConcurrency: 200}}
	if e := a.save(); e != nil {
		t.Fatal(e)
	}
	b := &App{project: "cf-vps", dir: a.dir}
	b.load()
	if b.state.Status != "paused" || b.state.Options.TCPConcurrency != 0 {
		t.Fatal(b.state.Status, b.state.Options)
	}
	c := &App{project: "ncv", dir: a.dir}
	c.load()
	if c.state.Status != "completed" {
		t.Fatal("NCV task behavior changed")
	}
}
