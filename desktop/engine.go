package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type work struct {
	Endpoint
	Index int
	TCP   float64
	Port  int
}

func buildConfig(templates []Template, batch []work) (map[string]any, error) {
	ins := []any{}
	outs := []any{map[string]any{"tag": "blocked", "protocol": "blackhole"}}
	rules := []any{}
	for i, w := range batch {
		out, e := parseTemplate(templates[w.Index])
		if e != nil {
			return nil, e
		}
		tag := fmt.Sprintf("candidate-%d", i)
		in := fmt.Sprintf("input-%d", i)
		out["tag"] = tag
		v := out["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
		v["address"] = w.IP
		v["port"] = w.Endpoint.Port
		outs = append(outs, out)
		ins = append(ins, map[string]any{"tag": in, "listen": "127.0.0.1", "port": w.Port, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": false}})
		rules = append(rules, map[string]any{"type": "field", "inboundTag": []string{in}, "outboundTag": tag})
	}
	return map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": ins, "outbounds": outs, "routing": map[string]any{"domainStrategy": "AsIs", "rules": rules}}, nil
}
func socksDial(ctx context.Context, proxy, address string) (net.Conn, error) {
	c, e := (&net.Dialer{}).DialContext(ctx, "tcp", proxy)
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			c.Close()
		}
	}()
	if d, yes := ctx.Deadline(); yes {
		c.SetDeadline(d)
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if _, e = c.Write([]byte{5, 1, 0}); e != nil {
		return nil, e
	}
	reply := make([]byte, 2)
	if _, e = io.ReadFull(c, reply); e != nil {
		return nil, e
	}
	if reply[0] != 5 || reply[1] != 0 {
		return nil, errors.New("SOCKS 协商失败")
	}
	host, p, e := net.SplitHostPort(address)
	if e != nil || len(host) > 255 {
		return nil, errors.New("目标地址无效")
	}
	port, e := strconv.Atoi(p)
	if e != nil {
		return nil, e
	}
	req := append([]byte{5, 1, 0, 3, byte(len(host))}, []byte(host)...)
	req = append(req, byte(port>>8), byte(port))
	if _, e = c.Write(req); e != nil {
		return nil, e
	}
	head := make([]byte, 4)
	if _, e = io.ReadFull(c, head); e != nil {
		return nil, e
	}
	if head[0] != 5 || head[1] != 0 {
		return nil, errors.New("节点连接目标失败")
	}
	n := 0
	switch head[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		b := []byte{0}
		if _, e = io.ReadFull(c, b); e != nil {
			return nil, e
		}
		n = int(b[0])
	default:
		return nil, errors.New("SOCKS 响应无效")
	}
	if _, e = io.CopyN(io.Discard, c, int64(n+2)); e != nil {
		return nil, e
	}
	c.SetDeadline(time.Time{})
	ok = true
	return c, nil
}
func probe(ctx context.Context, port int, target string, timeout time.Duration) Sample {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return socksDial(ctx, fmt.Sprintf("127.0.0.1:%d", port), address)
	}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, "GET", target, nil)
	start := time.Now()
	res, e := client.Do(req)
	if e != nil {
		return Sample{Error: "代理请求失败或超时"}
	}
	defer res.Body.Close()
	_, e = io.Copy(io.Discard, io.LimitReader(res.Body, 65537))
	if e != nil {
		return Sample{Error: "响应读取失败"}
	}
	expected := 204
	if target == "https://www.cloudflare.com/cdn-cgi/trace" {
		expected = 200
	}
	if res.StatusCode != expected {
		return Sample{Error: fmt.Sprintf("目标返回 HTTP %d", res.StatusCode)}
	}
	return Sample{OK: true, MS: float64(time.Since(start).Microseconds()) / 1000}
}
func (a *App) start() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.running {
		return errors.New("任务正在运行")
	}
	if a.state.SiteKind != "" && a.state.SiteKind != a.projectKind() {
		return errors.New("该任务属于另一项目，请使用对应的电脑程序")
	}
	if len(a.state.Candidates) == 0 {
		return errors.New("尚未创建任务")
	}
	if _, e := os.Stat(a.core); e != nil {
		return errors.New("未找到 core/xray.exe，请完整解压便携包")
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.running = true
	a.done = make(chan struct{})
	a.state.Status = "running"
	a.state.Error = ""
	go a.run(ctx)
	return nil
}
func (a *App) run(ctx context.Context) {
	var runErr error
	defer func() {
		a.mu.Lock()
		if runErr != nil {
			a.state.Status = "error"
			a.state.Error = runErr.Error()
		} else if ctx.Err() != nil {
			a.state.Status = "paused"
		} else {
			a.state.Status = "completed"
		}
		a.running = false
		a.cancel = nil
		done := a.done
		a.mu.Unlock()
		if e := a.save(); e != nil {
			a.mu.Lock()
			a.state.Status = "error"
			a.state.Error = "无法保存进度：" + e.Error()
			a.mu.Unlock()
		}
		close(done)
	}()
	a.mu.Lock()
	opts := a.state.Options
	candidates := append([]Endpoint(nil), a.state.Candidates...)
	templates := append([]Template(nil), a.state.Templates...)
	a.mu.Unlock()
	needsCore := false
	a.mu.Lock()
	for i, ep := range candidates {
		if !a.skipTCP() && !a.state.TCPDone[i] {
			needsCore = true
			break
		}
		if a.skipTCP() || a.state.TCPLatency[i] >= 0 {
			for ti := range templates {
				if _, ok := a.state.Results[resultKey(ti, ep)]; !ok {
					needsCore = true
					break
				}
			}
		}
		if needsCore {
			break
		}
	}
	a.mu.Unlock()
	if needsCore {
		if e := a.validateCore(ctx, templates); e != nil {
			if ctx.Err() == nil {
				runErr = e
			}
			return
		}
	}
	timeout := time.Duration(opts.Timeout * float64(time.Second))
	checkDone := make(chan struct{})
	go func() {
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-checkDone:
				return
			case <-tick.C:
				if e := a.save(); e != nil {
					a.mu.Lock()
					a.state.Error = "进度保存失败：" + e.Error()
					if a.cancel != nil {
						a.cancel()
					}
					a.mu.Unlock()
					return
				}
			}
		}
	}()
	defer close(checkDone)
	if !a.skipTCP() {
		jobs := make(chan int)
		var wg sync.WaitGroup
		for n := 0; n < opts.TCPConcurrency; n++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range jobs {
					if ctx.Err() != nil {
						return
					}
					check := a.tcpProbe
					if check == nil {
						check = dialTCP
					}
					ms, e := check(ctx, candidates[i], timeout)
					if ctx.Err() != nil {
						return
					}
					a.mu.Lock()
					a.state.TCPDone[i] = true
					a.state.TCPLatency[i] = -1
					if e == nil {
						a.state.TCPLatency[i] = ms
					}
					a.mu.Unlock()
				}
			}()
		}
	feed:
		for i := range candidates {
			a.mu.Lock()
			done := a.state.TCPDone[i]
			a.mu.Unlock()
			if done {
				continue
			}
			select {
			case jobs <- i:
			case <-ctx.Done():
				break feed
			}
		}
		close(jobs)
		wg.Wait()
		if ctx.Err() != nil {
			return
		}

	}
	batch := []work{}
	for i, ep := range candidates {
		a.mu.Lock()
		latency := a.state.TCPLatency[i]
		if a.skipTCP() {
			latency = 0
		}
		a.mu.Unlock()
		if latency < 0 {
			continue
		}
		for t := range templates {
			a.mu.Lock()
			_, done := a.state.Results[resultKey(t, ep)]
			a.mu.Unlock()
			if done {
				continue
			}
			batch = append(batch, work{Endpoint: ep, Index: t, TCP: latency})
			if len(batch) == 200 {
				if e := a.testBatch(ctx, templates, batch, opts); e != nil {
					if ctx.Err() == nil {
						runErr = e
					}
					return
				}
				batch = nil
			}
			if ctx.Err() != nil {
				return
			}
		}
	}
	if len(batch) > 0 {
		if e := a.testBatch(ctx, templates, batch, opts); e != nil && ctx.Err() == nil {
			runErr = e
		}
	}
}
func (a *App) testBatch(ctx context.Context, templates []Template, batch []work, opts Options) error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		err = a.testBatchOnce(ctx, templates, batch, opts)
		if err == nil || ctx.Err() != nil {
			return err
		}
		text := strings.ToLower(err.Error())
		if !strings.Contains(text, "failed to listen") && !strings.Contains(text, "address already in use") && !strings.Contains(text, "bind:") {
			return err
		}
	}
	return err
}
func (a *App) testBatchOnce(ctx context.Context, templates []Template, batch []work, opts Options) error {
	holders, e := reserveCorePorts(len(batch))
	if e != nil {
		return e
	}
	defer func() {
		for _, l := range holders {
			l.Close()
		}
	}()
	for i, l := range holders {
		batch[i].Port = l.Addr().(*net.TCPAddr).Port
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
	ports := []int{}
	for i, l := range holders {
		l.Close()
		ports = append(ports, batch[i].Port)
	}
	process, e := a.launchCore(ctx, path, ports, templates)
	if e != nil {
		return e
	}
	defer process.stop()
	parentCtx := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		select {
		case <-process.done:
			cancel()
		case <-watchDone:
		}
	}()
	jobs := make(chan work)
	var wg sync.WaitGroup
	for n := 0; n < opts.ProxyConcurrency; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for w := range jobs {
				if ctx.Err() != nil {
					return
				}
				t := templates[w.Index]
				r := Result{Endpoint: w.Endpoint, Template: w.Index, Name: t.Name, Region: t.Region, TCP: w.TCP, Status: "failed"}
				times := []float64{}
				for attempt := 0; attempt < opts.Attempts; attempt++ {
					s := probe(ctx, w.Port, opts.Target, time.Duration(opts.Timeout*float64(time.Second)))
					if ctx.Err() != nil {
						return
					}
					r.Samples = append(r.Samples, s)
					r.Attempts++
					if s.OK {
						r.Success++
						times = append(times, s.MS)
					} else {
						r.Error = s.Error
					}
					if attempt == 0 && !s.OK {
						break
					}
				}
				if r.Success == opts.Attempts {
					r.Status = "passed"
					r.Error = ""
				} else if r.Success > 0 {
					r.Status = "unstable"
				}
				if len(times) > 0 {
					sort.Float64s(times)
					r.Median = times[len(times)/2]
				}
				a.mu.Lock()
				a.state.Results[resultKey(w.Index, w.Endpoint)] = r
				a.mu.Unlock()
			}
		}()
	}
feed:
	for _, w := range batch {
		select {
		case jobs <- w:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	if parentCtx.Err() != nil {
		return parentCtx.Err()
	}
	if process.ended() {
		return a.coreError(fmt.Sprintf("Xray 测试中意外退出：%v", process.err), process.output.String(), templates)
	}
	return ctx.Err()
}
