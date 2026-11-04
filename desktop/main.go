package main

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed ui/*
var assets embed.FS
var version = "0.2.0-beta.1"

func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20)).Decode(v)
}
func (a *App) handler() http.Handler {
	mux := http.NewServeMux()
	ui, _ := fs.Sub(assets, "ui")
	mux.Handle("/", http.FileServer(http.FS(ui)))
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-NCV-Token")), []byte(a.token)) != 1 {
			http.Error(w, "Unauthorized", 401)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && origin != "http://"+r.Host {
			http.Error(w, "Invalid origin", 403)
			return
		}
		var err error
		switch r.URL.Path {
		case "/api/state":
			if r.Method != "GET" {
				break
			}
			a.mu.Lock()
			done, passed, stable := 0, 0, 0
			for i, d := range a.state.TCPDone {
				if d {
					done++
					if a.state.TCPLatency[i] >= 0 {
						passed++
					}
				}
			}
			for _, v := range a.state.Results {
				if v.Status == "passed" {
					stable++
				}
			}
			templates := append([]Template(nil), a.state.Templates...)
			for i := range templates {
				templates[i].Link = ""
			}
			reply(w, map[string]any{"version": version, "name": a.state.Name, "status": a.state.Status, "error": a.state.Error, "total": len(a.state.Candidates), "tcp_done": done, "tcp_passed": passed, "proxy_total": passed * len(templates), "proxy_done": len(a.state.Results), "passed": stable, "templates": templates, "site_kind": a.state.SiteKind, "site": a.state.Site, "job": a.state.Job, "options": a.state.Options})
			a.mu.Unlock()
			return
		case "/api/results":
			if r.Method != "GET" {
				break
			}
			a.mu.Lock()
			items := []Result{}
			for _, v := range a.state.Results {
				if filter := r.URL.Query().Get("status"); filter != "" && filter != v.Status {
					continue
				}
				items = append(items, v)
			}
			a.mu.Unlock()
			sort.Slice(items, func(i, j int) bool {
				if items[i].Status != items[j].Status {
					return items[i].Status == "passed"
				}
				return items[i].Median < items[j].Median
			})
			total := len(items)
			page, _ := strconv.Atoi(r.URL.Query().Get("page"))
			if page < 1 {
				page = 1
			}
			start := (page - 1) * 100
			if start > total {
				start = total
			}
			end := start + 100
			if end > total {
				end = total
			}
			reply(w, map[string]any{"items": items[start:end], "total": total, "page": page})
			return
		case "/api/create":
			if r.Method != "POST" {
				break
			}
			var q struct {
				Name, Input, Site, Job string
				SiteKind               string `json:"site_kind"`
				Port                   int
				Templates              []Template
				Options                Options
			}
			if err = decode(w, r, &q); err != nil {
				break
			}
			if q.SiteKind != "" && q.SiteKind != "ncv" && q.SiteKind != "cf-vps" {
				err = errors.New("不支持的网站类型")
				break
			}
			if !q.Options.BypassConfirmed {
				err = errors.New("请先关闭 TUN/VPN，或确认候选地址已排除代理")
				break
			}
			if q.Options.TCPConcurrency < 1 || q.Options.TCPConcurrency > 1000 || q.Options.ProxyConcurrency < 1 || q.Options.ProxyConcurrency > 50 || q.Options.Timeout < 1 || q.Options.Timeout > 30 || q.Options.Attempts < 1 || q.Options.Attempts > 5 {
				err = errors.New("并发、超时或复测次数超出范围")
				break
			}
			if q.Options.Target != "https://www.gstatic.com/generate_204" && q.Options.Target != "https://www.cloudflare.com/cdn-cgi/trace" {
				err = errors.New("不支持的测试目标")
				break
			}
			if len(q.Templates) == 0 || len(q.Templates) > 10 {
				err = errors.New("请提供 1–10 个节点模板")
				break
			}
			for i := range q.Templates {
				if _, err = parseTemplate(q.Templates[i]); err != nil {
					break
				}
				if q.Templates[i].Name == "" {
					q.Templates[i].Name = fmt.Sprintf("节点 %d", i+1)
				}
			}
			if err != nil {
				break
			}
			var candidates []Endpoint
			candidates, err = parseCandidates(q.Input, q.Port)
			if err != nil {
				break
			}
			if len(candidates)*len(q.Templates) > 500000 {
				err = errors.New("IP 与模板组合最多 50 万个")
				break
			}
			a.mu.Lock()
			if a.running {
				err = errors.New("请先暂停当前任务")
			} else {
				a.state = State{Name: q.Name, Status: "paused", Created: time.Now().Unix(), Input: q.Input, Options: q.Options, Templates: q.Templates, Candidates: candidates, TCPDone: make([]bool, len(candidates)), TCPLatency: make([]float64, len(candidates)), Results: map[string]Result{}, Site: q.Site, Job: q.Job, SiteKind: q.SiteKind}
			}
			a.mu.Unlock()
			if err == nil {
				err = a.save()
			}
			if err == nil {
				err = a.start()
			}
		case "/api/resume":
			if r.Method != "POST" {
				break
			}
			err = a.start()
		case "/api/pause":
			if r.Method != "POST" {
				break
			}
			a.mu.Lock()
			if a.cancel != nil {
				a.state.Status = "stopping"
				a.cancel()
			}
			a.mu.Unlock()
		case "/api/exit":
			if r.Method != "POST" {
				break
			}
			reply(w, map[string]bool{"ok": true})
			go func() { time.Sleep(200 * time.Millisecond); a.stop(); os.Exit(0) }()
			return
		case "/api/export":
			if r.Method != "GET" {
				break
			}
			a.mu.Lock()
			rows := []Result{}
			for _, v := range a.state.Results {
				if v.Status == "passed" {
					rows = append(rows, v)
				}
			}
			templates := append([]Template(nil), a.state.Templates...)
			a.mu.Unlock()
			sort.Slice(rows, func(i, j int) bool { return rows[i].Median < rows[j].Median })
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			if r.URL.Query().Get("format") == "csv" {
				w.Header().Set("Content-Type", "text/csv; charset=utf-8")
				w.Write([]byte{239, 187, 191})
				c := csv.NewWriter(w)
				c.Write([]string{"IP", "端口", "模板", "地区", "延迟ms", "成功次数"})
				for _, v := range rows {
					c.Write([]string{v.IP, strconv.Itoa(v.Port), v.Name, v.Region, fmt.Sprintf("%.2f", v.Median), fmt.Sprintf("%d/%d", v.Success, v.Attempts)})
				}
				c.Flush()
			} else {
				seen := map[string]bool{}
				for _, v := range rows {
					line := fmt.Sprintf("%s:%d", v.IP, v.Port)
					if r.URL.Query().Get("format") != "ips" {
						u, _ := url.Parse(templates[v.Template].Link)
						u.Host = net.JoinHostPort(v.IP, strconv.Itoa(v.Port))
						u.Fragment = fmt.Sprintf("%s %s %s:%d %.0fms", v.Region, v.Name, v.IP, v.Port, v.Median)
						line = u.String()
					}
					if !seen[line] {
						fmt.Fprintln(w, line)
						seen[line] = true
					}
				}
			}
			return
		case "/api/ncv":
			if r.Method != "POST" {
				break
			}
			var q struct {
				Site, User, Password, Action, Job string
				Kind                              string
			}
			if err = decode(w, r, &q); err != nil {
				break
			}
			var value any
			value, err = a.syncSite(q.Site, q.User, q.Password, q.Action, q.Job, q.Kind)
			if err == nil {
				reply(w, value)
				return
			}
		default:
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", 405)
			return
		}
		reply(w, map[string]bool{"ok": true})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil || host != "127.0.0.1" {
			http.Error(w, "Invalid host", 403)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		mux.ServeHTTP(w, r)
	})
}
func (a *App) stop() {
	a.mu.Lock()
	done := a.done
	running := a.running
	if a.cancel != nil {
		a.cancel()
	}
	a.mu.Unlock()
	if running {
		select {
		case <-done:
		case <-time.After(35 * time.Second):
		}
	}
	a.save()
}
func main() {
	noOpen := flag.Bool("no-open", false, "Do not open browser")
	coreFlag := flag.String("core", "", "Xray executable")
	dataFlag := flag.String("data", "", "Data directory")
	listenFlag := flag.String("listen", "127.0.0.1:49783", "Loopback address (port 0 for tests)")
	flag.Parse()
	exe, _ := os.Executable()
	core := filepath.Join(filepath.Dir(exe), "core", "xray.exe")
	if runtime.GOOS != "windows" {
		core = filepath.Join(filepath.Dir(exe), "core", "xray")
	}
	if *coreFlag != "" {
		core = *coreFlag
	}
	dir := *dataFlag
	if dir == "" {
		base, _ := os.UserConfigDir()
		dir = filepath.Join(base, "NCV-Desktop")
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		panic(e)
	}
	secret := make([]byte, 32)
	if _, e := rand.Read(secret); e != nil {
		panic(e)
	}
	ln, e := net.Listen("tcp4", *listenFlag)
	if e != nil {
		if !*noOpen {
			data, err := os.ReadFile(filepath.Join(dir, "打开界面.url"))
			if err == nil {
				for _, line := range strings.Split(string(data), "\n") {
					if strings.HasPrefix(line, "URL=http://127.0.0.1:") {
						openBrowser(strings.TrimSpace(strings.TrimPrefix(line, "URL=")))
					}
				}
			}
		}
		return
	}
	if !ln.Addr().(*net.TCPAddr).IP.IsLoopback() {
		ln.Close()
		panic("Only loopback is allowed")
	}
	a := &App{dir: dir, core: core, token: hex.EncodeToString(secret)}
	a.load()
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "core-") {
			os.RemoveAll(filepath.Join(dir, e.Name()))
		}
	}
	address := "http://" + ln.Addr().String() + "/#" + a.token
	os.WriteFile(filepath.Join(dir, "打开界面.url"), []byte("[InternetShortcut]\r\nURL="+address+"\r\n"), 0600)
	fmt.Println(address)
	if !*noOpen {
		openBrowser(address)
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)
	go func() { <-signals; a.stop(); os.Exit(0) }()
	server := &http.Server{Handler: a.handler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	if e = server.Serve(ln); e != nil && !errors.Is(e, http.ErrServerClosed) {
		a.stop()
	}
}
