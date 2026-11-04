package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCoreOutputBoundedAndPrivate(t *testing.T) {
	b := &coreOutput{}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				b.Write([]byte(strings.Repeat("x", 1024)))
				_ = b.String()
			}
		}()
	}
	wg.Wait()
	if len(b.String()) != 16384 {
		t.Fatal(len(b.String()))
	}
	a := testApp(t)
	raw := "Failed to start: invalid 11111111-1111-4111-8111-111111111111 original.example /fixture " + a.dir
	err := a.coreError("Xray 启动失败", raw, []Template{{Link: fixtureLink}})
	for _, secret := range []string{"11111111-1111-4111-8111-111111111111", "original.example", "/fixture", a.dir} {
		if strings.Contains(err.Error(), secret) {
			t.Fatal("Private value in diagnostics")
		}
	}
	saved, _ := os.ReadFile(filepath.Join(a.dir, "last-core-error.txt"))
	if !strings.Contains(string(saved), "Failed to start") {
		t.Fatal(string(saved))
	}
}
func TestReserve200DistinctCorePorts(t *testing.T) {
	ports, e := reserveCorePorts(200)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		for _, l := range ports {
			l.Close()
		}
	}()
	seen := map[int]bool{}
	for _, l := range ports {
		p := l.Addr().(*net.TCPAddr).Port
		if p < 18000 || p >= 28000 || seen[p] {
			t.Fatal(p)
		}
		seen[p] = true
		if other, e := net.Listen("tcp4", l.Addr().String()); e == nil {
			other.Close()
			t.Fatal("Reservation not held")
		}
	}
}
func TestCoreBindFailureIncludesCause(t *testing.T) {
	core := os.Getenv("NCV_TEST_XRAY")
	if core == "" {
		t.Skip("Set NCV_TEST_XRAY")
	}
	a := testApp(t)
	a.core = core
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	p := l.Addr().(*net.TCPAddr).Port
	cfg, e := buildConfig([]Template{{Link: fixtureLink}}, []work{{Endpoint: Endpoint{"127.0.0.1", 1}, Port: p}})
	if e != nil {
		t.Fatal(e)
	}
	path, e := a.writeCoreConfig(cfg)
	if e != nil {
		t.Fatal(e)
	}
	process, e := a.launchCore(context.Background(), path, []int{p}, []Template{{Link: fixtureLink}})
	if e == nil {
		defer process.stop()
		select {
		case <-process.done:
			e = a.coreError("Xray 启动失败", process.output.String(), nil)
		case <-time.After(2 * time.Second):
			t.Fatal("Expected occupied port failure")
		}
	}
	if !strings.Contains(e.Error(), "Failed to start") || !strings.Contains(e.Error(), "bind") {
		t.Fatal(e)
	}
}
func TestCoreConfigPreflightUsesRealCore(t *testing.T) {
	core := os.Getenv("NCV_TEST_XRAY")
	if core == "" {
		t.Skip("Set NCV_TEST_XRAY")
	}
	a := testApp(t)
	a.core = core
	if e := a.validateCore(context.Background(), []Template{{Link: fixtureLink}}); e != nil {
		t.Fatal(e)
	}
	invalid := strings.Replace(fixtureLink, "security=tls", "security=reality&pbk=invalid", 1)
	if e := a.validateCore(context.Background(), []Template{{Link: invalid}}); e == nil || !strings.Contains(e.Error(), "Failed to start") {
		t.Fatal(e)
	}
}

func TestRealCore200CandidateBatch(t *testing.T) {
	core := os.Getenv("NCV_TEST_XRAY")
	if core == "" {
		t.Skip("Set NCV_TEST_XRAY")
	}
	a := testApp(t)
	a.core = core
	batch := []work{}
	for i := 0; i < 200; i++ {
		batch = append(batch, work{Endpoint: Endpoint{"127.0.0.1", 1 + i}, TCP: 1})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	if e := a.testBatch(ctx, []Template{{Link: fixtureLink}}, batch, Options{ProxyConcurrency: 50, Timeout: 1, Attempts: 1, Target: "https://www.gstatic.com/generate_204"}); e != nil {
		t.Fatal(e)
	}
	if len(a.state.Results) != 200 {
		t.Fatal(len(a.state.Results))
	}
	for _, r := range a.state.Results {
		if r.Status != "failed" {
			t.Fatal("Closed fixture port passed")
		}
	}
}
