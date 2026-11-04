package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNCVNewTaskKeepsAllPreviousRecords(t *testing.T) {
	a := finishedApp(t)
	a.core = "missing-core"
	a.state.Name = "同名任务"
	if e := a.save(); e != nil {
		t.Fatal(e)
	}
	oldID := a.state.ID
	q := map[string]any{"name": "同名任务", "input": "1.1.1.1:443", "port": 443, "templates": []Template{{Link: fixtureLink}}, "options": savedOptions()}
	raw, _ := json.Marshal(q)
	req := httptest.NewRequest("POST", "http://127.0.0.1:1234/api/create", strings.NewReader(string(raw)))
	req.Header.Set("X-NCV-Token", a.token)
	w := httptest.NewRecorder()
	a.handler().ServeHTTP(w, req)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "未找到") {
		t.Fatal(w.Code, w.Body.String())
	}
	newID := a.state.ID
	if newID == oldID || !taskIDPattern.MatchString(newID) {
		t.Fatal("New task reused old ID")
	}
	list, e := a.taskList()
	if e != nil || len(list) != 2 {
		t.Fatal(list, e)
	}
	if e = a.selectTask(oldID); e != nil {
		t.Fatal(e)
	}
	if len(a.state.Results) != 1 || a.state.Candidates[0].Port != 8443 {
		t.Fatal("Old task lost")
	}
	if e = a.selectTask(newID); e != nil {
		t.Fatal(e)
	}
	if len(a.state.Results) != 0 || a.state.Candidates[0].IP != "1.1.1.1" {
		t.Fatal("Tasks mixed")
	}
	b := &App{project: "ncv", dir: a.dir}
	b.load()
	list, e = b.taskList()
	if e != nil || len(list) != 2 || b.state.ID != newID {
		t.Fatal("History not durable", e)
	}
}
func TestNCVHistoryRecoversCurrentPointerAndRejectsTraversal(t *testing.T) {
	a := finishedApp(t)
	if e := a.save(); e != nil {
		t.Fatal(e)
	}
	first := a.state.ID
	if e := a.save(); e != nil {
		t.Fatal(e)
	}
	a.state.ID = ""
	a.state.Name = "新任务"
	a.state.Created = 2
	if e := a.save(); e != nil {
		t.Fatal(e)
	}
	second := a.state.ID
	os.Remove(filepath.Join(a.dir, "tasks", first+".json"))
	list, e := a.taskList()
	if e != nil || len(list) != 2 {
		t.Fatal("Backup-only task disappeared", list, e)
	}
	for _, name := range []string{"state.json", "state.previous.json"} {
		os.WriteFile(filepath.Join(a.dir, name), []byte("broken"), 0600)
	}
	b := &App{project: "ncv", dir: a.dir}
	b.load()
	if b.state.ID != second {
		t.Fatal("Independent task checkpoint not recovered")
	}
	if e := b.selectTask(first); e != nil {
		t.Fatal(e)
	}
	if _, e := b.readTask("../../state"); e == nil {
		t.Fatal("Unsafe task ID")
	}
}
func TestNCVTaskSwitchRequiresFinishedPause(t *testing.T) {
	a := finishedApp(t)
	a.save()
	id := a.state.ID
	a.running = true
	if e := a.selectTask(id); e == nil {
		t.Fatal("Running task switched")
	}
	a.running = false
	a.done = make(chan struct{})
	if e := a.selectTask(id); e == nil {
		t.Fatal("Checkpoint still saving")
	}
	close(a.done)
}
func TestCFTaskStorageRemainsSeparate(t *testing.T) {
	a := finishedApp(t)
	a.project = "cf-vps"
	a.state.SiteKind = "cf-vps"
	if e := a.save(); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(a.dir, "tasks")); !os.IsNotExist(e) {
		t.Fatal("CF data written into NCV history")
	}
	if list, e := a.taskList(); e != nil || len(list) != 0 {
		t.Fatal(list, e)
	}
	if e := a.selectTask(a.state.ID); e == nil {
		t.Fatal("CF accepted NCV history selection")
	}
}
