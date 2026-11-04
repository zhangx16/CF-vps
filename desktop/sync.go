package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (a *App) ncv(site, user, password, action, job string) (any, error) {
	return a.syncSite(site, user, password, action, job, "ncv")
}
func (a *App) syncSite(site, user, password, action, job, kind string) (any, error) {
	if kind == "" {
		kind = "ncv"
	}
	if kind != "ncv" && kind != "cf-vps" {
		return nil, errors.New("不支持的网站类型")
	}

	u, e := url.Parse(strings.TrimRight(strings.TrimSpace(site), "/"))
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && u.Hostname() == "127.0.0.1")) {
		return nil, errors.New("请输入 HTTPS 网站地址")
	}
	if user == "" {
		user = "admin"
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request := func(path string, body any, out any) error {
		var reader io.Reader
		method := "GET"
		if body != nil {
			data, _ := json.Marshal(body)
			reader = bytes.NewReader(data)
			method = "POST"
		}
		req, _ := http.NewRequest(method, u.String()+path, reader)
		req.SetBasicAuth(user, password)
		csrf := "NCV"
		if kind == "cf-vps" {
			csrf = "CF-VPS"
		}
		req.Header.Set("X-Requested-With", csrf)
		req.Header.Set("Content-Type", "application/json")
		res, e := client.Do(req)
		if e != nil {
			return errors.New("连接网站失败，请检查地址与网络")
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return fmt.Errorf("网站返回 HTTP %d，请检查账号密码与任务", res.StatusCode)
		}
		return json.NewDecoder(io.LimitReader(res.Body, 16<<20)).Decode(out)
	}
	switch action {
	case "jobs":
		var out any
		e = request("/api/jobs", nil, &out)
		if e == nil && kind == "cf-vps" {
			if jobs, ok := out.([]any); ok {
				for _, raw := range jobs {
					if j, ok := raw.(map[string]any); ok {
						config, _ := j["config"].(map[string]any)
						name, _ := config["task_name"].(string)
						if name == "" {
							name, _ = config["provider_name"].(string)
						}
						if name == "" {
							name = "CF VPS 测试"
						}
						j["name"] = name
						j["passed"] = j["hits"]
					}
				}
			}
		}
		return out, e
	case "pull":
		if job == "" {
			return nil, errors.New("请选择网站任务")
		}
		lines := []string{}
		seen := map[string]bool{}
		cursor := ""
		cursors := map[string]bool{}
		for page := 1; ; page++ {
			var out struct {
				Items []Endpoint `json:"items"`
				Pages int        `json:"pages"`
				Next  string     `json:"next_cursor"`
			}
			path := fmt.Sprintf("/api/results?id=%s&limit=500&page=%d&sort=latency", url.QueryEscape(job), page)
			if kind == "cf-vps" {
				path = "/api/results?" + url.Values{"id": {job}, "view": {"hits"}, "sort": {"ip"}, "cursor": {cursor}}.Encode()
			}
			if e = request(path, nil, &out); e != nil {
				return nil, e
			}
			for _, ep := range out.Items {
				if !publicIPv4(ep.IP) || ep.Port < 1 || ep.Port > 65535 {
					return nil, errors.New("网站返回了无效候选")
				}
				key := fmt.Sprintf("%s:%d", ep.IP, ep.Port)
				if !seen[key] {
					seen[key] = true
					lines = append(lines, key)
				}
			}
			if len(lines) > 200000 {
				return nil, errors.New("超过 20 万候选，请先在网站筛选")
			}
			if kind == "cf-vps" {
				if out.Next == "" {
					break
				}
				if cursors[out.Next] {
					return nil, errors.New("网站返回重复的分页游标")
				}
				cursors[out.Next] = true
				cursor = out.Next
			} else if page >= out.Pages || len(out.Items) == 0 {
				break
			}
		}
		return map[string]any{"input": strings.Join(lines, "\n"), "total": len(lines)}, nil
	case "push":
		a.mu.Lock()
		sourceKind := a.state.SiteKind
		if sourceKind == "" {
			sourceKind = "ncv"
		}
		if strings.TrimRight(strings.TrimSpace(site), "/") != strings.TrimRight(strings.TrimSpace(a.state.Site), "/") || job != a.state.Job || kind != sourceKind {
			a.mu.Unlock()
			return nil, errors.New("请回填到创建本次本地任务时对应的网站任务")
		}
		eps := []Endpoint{}
		seen := map[string]bool{}
		for _, r := range a.state.Results {
			key := fmt.Sprintf("%s:%d", r.IP, r.Port)
			if r.Status == "passed" && !seen[key] {
				seen[key] = true
				eps = append(eps, r.Endpoint)
			}
		}
		a.mu.Unlock()
		if len(eps) == 0 {
			return nil, errors.New("没有全部复测通过的结果")
		}
		added, matched := 0, 0
		for i := 0; i < len(eps); i += 200 {
			end := i + 200
			if end > len(eps) {
				end = len(eps)
			}
			var out struct {
				Added   int        `json:"added"`
				Matched []Endpoint `json:"matched"`
			}
			if e = request("/api/confirmed-import", map[string]any{"id": job, "endpoints": eps[i:end]}, &out); e != nil {
				return nil, e
			}
			added += out.Added
			matched += len(out.Matched)
		}
		return map[string]any{"added": added, "matched": matched, "total": len(eps)}, nil
	}
	return nil, errors.New("无效操作")
}
