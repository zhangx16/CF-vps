package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Endpoint struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}
type Sample struct {
	OK    bool    `json:"ok"`
	MS    float64 `json:"ms,omitempty"`
	Error string  `json:"error,omitempty"`
}
type Result struct {
	Endpoint
	Template int      `json:"template"`
	Name     string   `json:"name"`
	Region   string   `json:"region"`
	Status   string   `json:"status"`
	TCP      float64  `json:"tcp_ms"`
	Success  int      `json:"success"`
	Attempts int      `json:"attempts"`
	Median   float64  `json:"median_ms"`
	Samples  []Sample `json:"samples,omitempty"`
	Error    string   `json:"error,omitempty"`
}
type Template struct {
	Name   string `json:"name"`
	Region string `json:"region"`
	Link   string `json:"link,omitempty"`
}
type Options struct {
	TCPConcurrency   int     `json:"tcp_concurrency"`
	ProxyConcurrency int     `json:"proxy_concurrency"`
	Timeout          float64 `json:"timeout"`
	Attempts         int     `json:"attempts"`
	Target           string  `json:"target"`
	BypassConfirmed  bool    `json:"bypass_confirmed"`
}
type State struct {
	SiteKind   string            `json:"site_kind,omitempty"`
	Name       string            `json:"name"`
	Status     string            `json:"status"`
	Created    int64             `json:"created"`
	Options    Options           `json:"options"`
	Input      string            `json:"input"`
	Templates  []Template        `json:"templates"`
	Candidates []Endpoint        `json:"candidates"`
	TCPDone    []bool            `json:"tcp_done"`
	TCPLatency []float64         `json:"tcp_latency"`
	Results    map[string]Result `json:"results"`
	Error      string            `json:"error"`
	Site       string            `json:"site,omitempty"`
	Job        string            `json:"job,omitempty"`
}
type App struct {
	tcpProbe func(context.Context, Endpoint, time.Duration) (float64, error)
	project  string
	mu       sync.Mutex
	state    State
	dir      string
	core     string
	cancel   context.CancelFunc
	running  bool
	done     chan struct{}
	token    string
	saveMu   sync.Mutex
}

var uuidRE = regexp.MustCompile(`(?i)^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$`)
var publicDeny = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3"}

func publicIPv4(value string) bool {
	ip, e := netip.ParseAddr(value)
	if e != nil || !ip.Is4() {
		return false
	}
	for _, n := range publicDeny {
		if netip.MustParsePrefix(n).Contains(ip) {
			return false
		}
	}
	return true
}
func parseCandidates(input string, port int) ([]Endpoint, error) {
	if len(input) > 4<<20 || port < 1 || port > 65535 {
		return nil, errors.New("候选输入过大或默认端口无效")
	}
	out := []Endpoint{}
	seen := map[string]bool{}
	for _, line := range strings.Split(input, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		address, p := line, port
		if strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			if len(parts) != 2 {
				return nil, errors.New("只支持 IPv4 / IPv4:端口 / CIDR:端口")
			}
			address = parts[0]
			n, e := strconv.Atoi(parts[1])
			if e != nil || n < 1 || n > 65535 {
				return nil, errors.New("候选端口无效")
			}
			p = n
		}
		if !strings.Contains(address, "/") {
			address += "/32"
		}
		prefix, e := netip.ParsePrefix(address)
		if e != nil || !prefix.Addr().Is4() || prefix.Bits() < 15 {
			return nil, errors.New("需要公网 IPv4，单段不超过 /15")
		}
		prefix = prefix.Masked()
		count := 1 << uint(32-prefix.Bits())
		ip := prefix.Addr()
		for i := 0; i < count; i++ {
			cur := ip.String()
			ip = ip.Next()
			if prefix.Bits() < 31 && (i == 0 || i == count-1) {
				continue
			}
			if !publicIPv4(cur) {
				return nil, errors.New("不支持非公网 IPv4 候选")
			}
			key := fmt.Sprintf("%s:%d", cur, p)
			if !seen[key] {
				seen[key] = true
				out = append(out, Endpoint{cur, p})
			}
			if len(out) > 200000 {
				return nil, errors.New("每个任务最多 20 万个不同候选")
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("请输入候选 IP")
	}
	return out, nil
}
func parseTemplate(t Template) (map[string]any, error) {
	if len(t.Link) > 8192 || strings.ContainsAny(t.Link, "\r\n") {
		return nil, errors.New("节点链接格式无效")
	}
	u, e := url.Parse(strings.TrimSpace(t.Link))
	if e != nil || u.Scheme != "vless" || u.User == nil || !uuidRE.MatchString(u.User.Username()) || u.Hostname() == "" {
		return nil, errors.New("仅支持有效 VLESS 节点链接")
	}
	if _, ok := u.User.Password(); ok {
		return nil, errors.New("VLESS 链接无效")
	}
	q := u.Query()
	allowed := map[string]bool{}
	for _, k := range strings.Fields("encryption security sni type host path fp alpn flow pbk sid spx serviceName mode authority allowInsecure headerType") {
		allowed[k] = true
	}
	for k, values := range q {
		if len(values) != 1 {
			return nil, fmt.Errorf("模板参数 %s 重复", k)
		}
		if !allowed[k] {
			return nil, fmt.Errorf("不支持模板参数 %s", k)
		}
	}
	get := func(k, d string) string {
		v := q.Get(k)
		if v == "" {
			return d
		}
		return v
	}
	security := get("security", "tls")
	network := get("type", "tcp")
	if network == "raw" {
		network = "tcp"
	}
	if security != "tls" && security != "reality" {
		return nil, errors.New("仅支持 TLS / Reality")
	}
	if get("encryption", "none") != "none" || get("headerType", "none") != "none" {
		return nil, errors.New("不支持当前 VLESS 加密或伪装参数")
	}
	if q.Get("allowInsecure") == "1" || q.Get("allowInsecure") == "true" {
		return nil, errors.New("请使用有效证书，不支持关闭 TLS 校验")
	}
	host := get("host", u.Hostname())
	sni := get("sni", host)
	stream := map[string]any{"network": network, "security": security}
	if security == "tls" {
		tls := map[string]any{"serverName": sni, "allowInsecure": false}
		if fp := q.Get("fp"); fp != "" {
			tls["fingerprint"] = fp
		}
		if alpn := q.Get("alpn"); alpn != "" {
			tls["alpn"] = strings.Split(alpn, ",")
		}
		stream["tlsSettings"] = tls
	} else {
		if q.Get("pbk") == "" {
			return nil, errors.New("Reality 缺少公钥")
		}
		stream["realitySettings"] = map[string]any{"serverName": sni, "fingerprint": get("fp", "chrome"), "password": q.Get("pbk"), "shortId": q.Get("sid"), "spiderX": get("spx", "/")}
	}
	switch network {
	case "ws", "httpupgrade":
		path := get("path", "/")
		if !strings.HasPrefix(path, "/") {
			return nil, errors.New("路径须以 / 开头")
		}
		key := "wsSettings"
		if network == "httpupgrade" {
			key = "httpupgradeSettings"
		}
		stream[key] = map[string]any{"path": path, "host": host}
	case "grpc":
		stream["grpcSettings"] = map[string]any{"serviceName": q.Get("serviceName"), "multiMode": q.Get("mode") == "multi", "authority": q.Get("authority")}
	case "tcp":
	default:
		return nil, errors.New("支持 WS / TCP / gRPC / HTTPUpgrade；其他传输暂不支持")
	}
	user := map[string]any{"id": u.User.Username(), "encryption": "none"}
	if flow := q.Get("flow"); flow != "" {
		if network != "tcp" {
			return nil, errors.New("flow 仅支持 TCP 模板")
		}
		user["flow"] = flow
	}
	return map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": u.Hostname(), "port": 443, "users": []any{user}}}}, "streamSettings": stream}, nil
}
func resultKey(t int, ep Endpoint) string { return fmt.Sprintf("%d/%s:%d", t, ep.IP, ep.Port) }
func (a *App) save() error {
	a.saveMu.Lock()
	defer a.saveMu.Unlock()
	a.mu.Lock()
	data, e := json.Marshal(a.state)
	a.mu.Unlock()
	if e != nil {
		return e
	}
	next := filepath.Join(a.dir, "state.next.json")
	if e = os.WriteFile(next, data, 0600); e != nil {
		return e
	}
	target := filepath.Join(a.dir, "state.json")
	backup := filepath.Join(a.dir, "state.previous.json")
	os.Remove(backup)
	if _, e = os.Stat(target); e == nil {
		if e = os.Rename(target, backup); e != nil {
			return e
		}
	}
	if e = os.Rename(next, target); e != nil {
		os.Rename(backup, target)
		return e
	}
	return nil
}
func (a *App) load() {
	for _, name := range []string{"state.json", "state.previous.json"} {
		data, e := os.ReadFile(filepath.Join(a.dir, name))
		if e != nil {
			continue
		}
		var state State
		if json.Unmarshal(data, &state) != nil {
			continue
		}
		if state.Status == "running" || state.Status == "stopping" {
			state.Status = "paused"
		}
		if state.Results == nil {
			state.Results = map[string]Result{}
		}
		a.state = state
		a.prepareProfileState()
		return
	}
	a.state = State{Status: "idle", Results: map[string]Result{}}
}
func dialTCP(ctx context.Context, ep Endpoint, timeout time.Duration) (float64, error) {
	start := time.Now()
	c, e := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", net.JoinHostPort(ep.IP, strconv.Itoa(ep.Port)))
	if e != nil {
		return 0, e
	}
	c.Close()
	return float64(time.Since(start).Microseconds()) / 1000, nil
}
