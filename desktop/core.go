package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Keep a bounded tail in memory; never persist raw core output.
type coreOutput struct {
	mu   sync.Mutex
	data []byte
}

func (b *coreOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	const limit = 16384
	if len(p) >= limit {
		b.data = append(b.data[:0], p[len(p)-limit:]...)
	} else {
		b.data = append(b.data, p...)
		if len(b.data) > limit {
			b.data = append([]byte(nil), b.data[len(b.data)-limit:]...)
		}
	}
	return n, nil
}
func (b *coreOutput) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.ToValidUTF8(string(b.data), "?")
}

var diagnosticUUID = regexp.MustCompile(`(?i)[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}`)

func (a *App) coreError(message, output string, templates []Template) error {
	detail := strings.TrimSpace(output)
	if i := strings.LastIndex(detail, "Failed to start:"); i >= 0 {
		detail = detail[i:]
	}
	if len(detail) > 4000 {
		detail = detail[len(detail)-4000:]
	}
	detail = diagnosticUUID.ReplaceAllString(detail, "[UUID]")
	for _, t := range templates {
		u, e := url.Parse(t.Link)
		if e != nil {
			continue
		}
		secrets := []string{t.Link, u.Hostname()}
		for _, values := range u.Query() {
			secrets = append(secrets, values...)
		}
		for _, s := range secrets {
			if len(s) >= 4 {
				detail = strings.ReplaceAll(detail, s, "[节点参数]")
			}
		}
	}
	detail = strings.ReplaceAll(detail, a.dir, "[本机数据目录]")
	text := message
	if detail != "" {
		text += "\n" + detail
	}
	os.WriteFile(filepath.Join(a.dir, "last-core-error.txt"), []byte(time.Now().Format(time.RFC3339)+"\n"+text+"\n"), 0600)
	return fmt.Errorf("%s", text)
}

type coreProcess struct {
	cmd     *exec.Cmd
	output  *coreOutput
	done    chan struct{}
	err     error
	release func()
}

func (p *coreProcess) stop() { p.cmd.Process.Kill(); <-p.done; p.release() }
func (p *coreProcess) ended() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}
func (a *App) launchCore(ctx context.Context, path string, ports []int, templates []Template) (*coreProcess, error) {
	cmd := exec.CommandContext(ctx, a.core, "run", "-c", path)
	cmd.Dir = filepath.Dir(a.core)
	cmd.WaitDelay = 2 * time.Second
	prepareCommand(cmd)
	output := &coreOutput{}
	cmd.Stdout = output
	cmd.Stderr = output
	if e := cmd.Start(); e != nil {
		return nil, a.coreError("无法启动 Xray："+e.Error(), "", templates)
	}
	p := &coreProcess{cmd: cmd, output: output, done: make(chan struct{}), release: attachProcess(cmd)}
	go func() { p.err = cmd.Wait(); close(p.done) }()
	deadline := time.Now().Add(12 * time.Second)
	for _, port := range ports {
		ready := false
		for time.Now().Before(deadline) {
			if p.ended() {
				e := a.coreError(fmt.Sprintf("Xray 启动失败：%v", p.err), output.String(), templates)
				p.stop()
				return nil, e
			}
			if ctx.Err() != nil {
				p.stop()
				return nil, ctx.Err()
			}
			c, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
			if e == nil {
				c.Close()
				ready = true
				break
			}
			time.Sleep(30 * time.Millisecond)
		}
		if !ready {
			p.stop()
			return nil, a.coreError("Xray 启动超时", output.String(), templates)
		}
	}
	if p.ended() {
		e := a.coreError(fmt.Sprintf("Xray 启动失败：%v", p.err), output.String(), templates)
		p.stop()
		return nil, e
	}
	return p, nil
}
func (a *App) writeCoreConfig(cfg map[string]any) (string, error) {
	data, e := json.Marshal(cfg)
	if e != nil {
		return "", e
	}
	dir, e := os.MkdirTemp(a.dir, "core-")
	if e != nil {
		return "", e
	}
	path := filepath.Join(dir, "config.json")
	if e = os.WriteFile(path, data, 0600); e != nil {
		os.RemoveAll(dir)
		return "", e
	}
	return path, nil
}
func (a *App) validateCore(ctx context.Context, templates []Template) error {
	batch := []work{}
	for i := range templates {
		batch = append(batch, work{Endpoint: Endpoint{"1.1.1.1", 443}, Index: i, Port: 20000 + i})
	}
	cfg, e := buildConfig(templates, batch)
	if e != nil {
		return e
	}
	path, e := a.writeCoreConfig(cfg)
	if e != nil {
		return e
	}
	defer os.RemoveAll(filepath.Dir(path))
	testCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(testCtx, a.core, "run", "-test", "-c", path)
	cmd.Dir = filepath.Dir(a.core)
	cmd.WaitDelay = 2 * time.Second
	prepareCommand(cmd)
	output := &coreOutput{}
	cmd.Stdout = output
	cmd.Stderr = output
	if e = cmd.Start(); e != nil {
		return a.coreError("无法检查 Xray 配置："+e.Error(), "", templates)
	}
	release := attachProcess(cmd)
	defer release()
	e = cmd.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if testCtx.Err() != nil {
		return a.coreError("Xray 配置检查超时", output.String(), templates)
	}
	if e != nil {
		return a.coreError("Xray 配置检查失败："+e.Error(), output.String(), templates)
	}
	return nil
}

// Avoid the default Windows client ephemeral range. Keep every reservation open
// until the config is ready, then retry with new ports if another process wins.
func reserveCorePorts(count int) ([]net.Listener, error) {
	const first, size = 18000, 10000
	seed, e := rand.Int(rand.Reader, big.NewInt(size))
	if e != nil {
		return nil, e
	}
	start := int(seed.Int64())
	holders := []net.Listener{}
	var last error
	for i := 0; i < size && len(holders) < count; i++ {
		port := first + (start+i)%size
		l, e := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		if e != nil {
			last = e
			continue
		}
		holders = append(holders, l)
	}
	if len(holders) != count {
		for _, l := range holders {
			l.Close()
		}
		return nil, fmt.Errorf("无法分配本地测试端口：%v", last)
	}
	return holders, nil
}
