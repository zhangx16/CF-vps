package main

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestEveryExportUsesCurrentTaskName(t *testing.T) {
	a := finishedApp(t)
	a.state.Name = "香港/晚间:测试"
	for _, format := range []string{"csv", "links", "ips"} {
		req := httptest.NewRequest("GET", "http://127.0.0.1:1234/api/export?format="+format, nil)
		req.Header.Set("X-NCV-Token", a.token)
		w := httptest.NewRecorder()
		a.handler().ServeHTTP(w, req)
		header, _ := url.PathUnescape(w.Header().Get("Content-Disposition"))
		ext := ".txt"
		if format == "csv" {
			ext = ".csv"
		}
		if w.Code != 200 || !strings.Contains(header, "香港_晚间_测试"+ext) {
			t.Fatal(w.Code, header)
		}
	}
}
func TestExportRejectsStaleTaskSelection(t *testing.T) {
	a := finishedApp(t)
	a.save()
	req := httptest.NewRequest("GET", "http://127.0.0.1:1234/api/export?task=another-task", nil)
	req.Header.Set("X-NCV-Token", a.token)
	w := httptest.NewRecorder()
	a.handler().ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
}
