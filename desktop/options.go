package main

import (
	"errors"
	"fmt"
	"math"
)

func (a *App) validateOptions(opts Options) (Options, error) {
	if !opts.BypassConfirmed {
		return opts, errors.New("请先关闭 TUN/VPN，或确认候选地址已排除代理")
	}
	if (!a.skipTCP() && (opts.TCPConcurrency < 1 || opts.TCPConcurrency > 1000)) || opts.ProxyConcurrency < 1 || opts.ProxyConcurrency > 50 || math.IsNaN(opts.Timeout) || opts.Timeout < 1 || opts.Timeout > 30 || opts.Attempts < 1 || opts.Attempts > 5 {
		return opts, errors.New("并发、超时或复测次数超出范围")
	}
	if opts.Target != "https://www.gstatic.com/generate_204" && opts.Target != "https://www.cloudflare.com/cdn-cgi/trace" {
		return opts, errors.New("不支持的测试目标")
	}
	if a.skipTCP() {
		opts.TCPConcurrency = 0
	}
	return opts, nil
}

// Called with controlMu held by the API, so a new task cannot replace this task
// between applying options, saving its checkpoint and starting its workers.
func (a *App) resumeWithOptions(opts *Options) error {
	var next Options
	var err error
	if opts != nil {
		if next, err = a.validateOptions(*opts); err != nil {
			return err
		}
	}
	a.mu.Lock()
	if a.busyLocked() {
		a.mu.Unlock()
		return errors.New("任务仍在运行或保存暂停进度，请等待暂停完成")
	}
	if len(a.state.Candidates) == 0 {
		a.mu.Unlock()
		return errors.New("尚未创建任务")
	}
	if a.state.SiteKind != "" && a.state.SiteKind != a.projectKind() {
		a.mu.Unlock()
		return errors.New("请使用对应项目的电脑程序")
	}
	previous := a.state.Options
	backfilled := []string{}
	if opts != nil {
		for key, r := range a.state.Results {
			if r.Target == "" {
				r.Target = previous.Target
				a.state.Results[key] = r
				backfilled = append(backfilled, key)
			}
		}
		a.state.Options = next
	}
	a.mu.Unlock()
	if opts != nil {
		if err = a.save(); err != nil {
			a.mu.Lock()
			a.state.Options = previous
			for _, key := range backfilled {
				r := a.state.Results[key]
				r.Target = ""
				a.state.Results[key] = r
			}
			a.mu.Unlock()
			return fmt.Errorf("续测参数保存失败，未启动任务：%w", err)
		}
	}
	return a.start()
}

// running becomes false before the final snapshot finishes. Do not permit a
// resume or replacement until the old worker has closed its completion channel.
func (a *App) busyLocked() bool {
	if a.running {
		return true
	}
	if a.done != nil {
		select {
		case <-a.done:
		default:
			return true
		}
	}
	return false
}
