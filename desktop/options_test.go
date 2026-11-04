package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func savedOptions() Options {
	return Options{TCPConcurrency: 200, ProxyConcurrency: 10, Timeout: 6, Attempts: 3, Target: "https://www.gstatic.com/generate_204", BypassConfirmed: true}
}
func finishedApp(t *testing.T) *App {
	a := testApp(t)
	a.core = filepath.Join(a.dir, "unused-core")
	os.WriteFile(a.core, []byte("completed work needs no core launch"), 0600)
	ep := Endpoint{"8.8.8.8", 8443}
	a.state = State{Name: "原任务", Status: "paused", Created: 1, Options: savedOptions(), Candidates: []Endpoint{ep}, TCPDone: []bool{true}, TCPLatency: []float64{2}, Templates: []Template{{Link: fixtureLink}}, Results: map[string]Result{resultKey(0, ep): {Endpoint: ep, Status: "passed", Success: 3, Attempts: 3}}}
	return a
}
func TestResumeAppliesOptionsToRemainingWork(t *testing.T) {
	a := finishedApp(t)
	next := savedOptions()
	next.TCPConcurrency = 500
	next.ProxyConcurrency = 7
	next.Timeout = 9
	next.Attempts = 5
	next.Target = "https://www.cloudflare.com/cdn-cgi/trace"
	if e := a.resumeWithOptions(&next); e != nil {
		t.Fatal(e)
	}
	select {
	case <-a.done:
	case <-time.After(time.Second * 3):
		t.Fatal("resume hung")
	}
	if a.state.Options != next || a.state.Status != "completed" || len(a.state.Results) != 1 {
		t.Fatal(a.state.Options, a.state.Status)
	}
	for _, r := range a.state.Results {
		if r.Success != 3 || r.Attempts != 3 || r.Target != savedOptions().Target {
			t.Fatal("Existing results changed", r)
		}
	}
	b := &App{project: "ncv", dir: a.dir}
	b.load()
	if b.state.Options != next || len(b.state.Results) != 1 {
		t.Fatal("New options not durable")
	}
}
func TestInvalidResumeOptionsAreAtomic(t *testing.T) {
	a := finishedApp(t)
	before, _ := json.Marshal(a.state)
	for _, change := range []func(*Options){func(o *Options) { o.TCPConcurrency = 0 }, func(o *Options) { o.ProxyConcurrency = 51 }, func(o *Options) { o.Timeout = 0 }, func(o *Options) { o.Attempts = 0 }, func(o *Options) { o.Target = "https://invalid.example" }, func(o *Options) { o.BypassConfirmed = false }} {
		next := savedOptions()
		change(&next)
		if e := a.resumeWithOptions(&next); e == nil {
			t.Fatal("Invalid options accepted")
		}
		after, _ := json.Marshal(a.state)
		if string(before) != string(after) {
			t.Fatal("Invalid request mutated task")
		}
	}
}
func TestResumeWaitsForPauseCheckpoint(t *testing.T) {
	a := finishedApp(t)
	a.done = make(chan struct{})
	next := savedOptions()
	next.ProxyConcurrency = 2
	if e := a.resumeWithOptions(&next); e == nil || !strings.Contains(e.Error(), "保存") {
		t.Fatal(e)
	}
	if a.state.Options.ProxyConcurrency != 10 {
		t.Fatal("Unfinished pause mutated options")
	}
	close(a.done)
}
func TestResumeSaveFailureLeavesTaskUnchanged(t *testing.T) {
	a := finishedApp(t)
	if e := a.save(); e != nil {
		t.Fatal(e)
	}
	os.RemoveAll(filepath.Join(a.dir, "tasks"))
	os.WriteFile(filepath.Join(a.dir, "tasks"), []byte("blocks archive write"), 0600)
	next := savedOptions()
	next.ProxyConcurrency = 2
	if e := a.resumeWithOptions(&next); e == nil {
		t.Fatal("Save error ignored")
	}
	if a.running || a.state.Options != savedOptions() {
		t.Fatal("Failed save started task")
	}
	for _, r := range a.state.Results {
		if r.Target != "" {
			t.Fatal("Failed save changed result metadata")
		}
	}
}
