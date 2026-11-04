package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCFSiteCursorDedupAndReturnContract(t *testing.T) {
	a := testApp(t)
	pulls, posts := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, _ := r.BasicAuth()
		if u != "admin" || p != "session-only" {
			t.Error("auth")
		}
		if r.Header.Get("X-Requested-With") != "CF-VPS" {
			t.Error("Wrong CSRF header")
		}
		switch r.URL.Path {
		case "/api/jobs":
			reply(w, []any{map[string]any{"id": "cf-job", "hits": 400, "config": map[string]any{"task_name": "CF 原始任务"}}})
		case "/api/results":
			pulls++
			if r.URL.Query().Get("view") != "hits" || r.URL.Query().Get("sort") != "ip" {
				t.Error(r.URL)
			}
			if r.URL.Query().Get("cursor") == "" {
				reply(w, map[string]any{"items": []Endpoint{{"8.8.8.8", 443}, {"8.8.8.8", 8443}}, "next_cursor": "page-two"})
			} else {
				if r.URL.Query().Get("cursor") != "page-two" {
					t.Error("Bad cursor")
				}
				reply(w, map[string]any{"items": []Endpoint{{"8.8.8.8", 8443}, {"1.1.1.1", 443}}, "next_cursor": ""})
			}
		case "/api/confirmed-import":
			posts++
			var body map[string]json.RawMessage
			json.NewDecoder(r.Body).Decode(&body)
			if len(body) != 2 || body["id"] == nil || body["endpoints"] == nil {
				t.Error("Unexpected return fields")
			}
			reply(w, map[string]any{"added": 1, "matched": []Endpoint{{"8.8.8.8", 8443}}})
		default:
			t.Error(r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	jobs, e := a.syncSite(server.URL, "admin", "session-only", "jobs", "", "cf-vps")
	if e != nil {
		t.Fatal(e)
	}
	job := jobs.([]any)[0].(map[string]any)
	if job["name"] != "CF 原始任务" || job["passed"] != float64(400) {
		t.Fatal(job)
	}
	out, e := a.syncSite(server.URL, "admin", "session-only", "pull", "cf-job", "cf-vps")
	if e != nil {
		t.Fatal(e)
	}
	if pulls != 2 || out.(map[string]any)["total"] != 3 {
		t.Fatal(out, pulls)
	}
	input := out.(map[string]any)["input"].(string)
	if strings.Count(input, "8.8.8.8:8443") != 1 {
		t.Fatal(input)
	}
	a.state.Site = server.URL
	a.state.Job = "cf-job"
	a.state.SiteKind = "cf-vps"
	a.state.Results["fixture"] = Result{Endpoint: Endpoint{"8.8.8.8", 8443}, Status: "passed"}
	if _, e = a.syncSite(server.URL, "admin", "session-only", "push", "cf-job", "ncv"); e == nil {
		t.Fatal("Wrong project accepted")
	}
	if _, e = a.syncSite(server.URL, "admin", "session-only", "push", "cf-job", "cf-vps"); e != nil {
		t.Fatal(e)
	}
	if posts != 1 {
		t.Fatal(posts)
	}
}
func TestCFSiteRepeatedCursorRejected(t *testing.T) {
	a := testApp(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]any{"items": []Endpoint{{"8.8.8.8", 443}}, "next_cursor": "same"})
	}))
	defer server.Close()
	if _, e := a.syncSite(server.URL, "", "", "pull", "job", "cf-vps"); e == nil || !strings.Contains(e.Error(), "重复") {
		t.Fatal(e)
	}
}
