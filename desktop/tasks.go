package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var taskIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

type TaskInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Created  int64  `json:"created"`
	Status   string `json:"status"`
	Total    int    `json:"total"`
	TCPDone  int    `json:"tcp_done"`
	NodeDone int    `json:"node_done"`
	Passed   int    `json:"passed"`
}

func newTaskID() (string, error) {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return hex.EncodeToString(b), nil
}
func (a *App) historyEnabled() bool { return a.projectKind() == "ncv" }
func taskInfo(s State) TaskInfo {
	v := TaskInfo{ID: s.ID, Name: s.Name, Created: s.Created, Status: s.Status, Total: len(s.Candidates), NodeDone: len(s.Results)}
	for _, done := range s.TCPDone {
		if done {
			v.TCPDone++
		}
	}
	for _, r := range s.Results {
		if r.Status == "passed" {
			v.Passed++
		}
	}
	return v
}
func normalizeTask(s *State) error {
	if len(s.Candidates) != len(s.TCPDone) || len(s.Candidates) != len(s.TCPLatency) {
		return errors.New("任务检查点不完整")
	}
	if s.Status == "running" || s.Status == "stopping" {
		s.Status = "paused"
	}
	if s.Results == nil {
		s.Results = map[string]Result{}
	}
	return nil
}
func writeCheckpoint(target, backup, next string, data []byte) error {
	f, e := os.OpenFile(next, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(data)
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	if e = os.Remove(backup); e != nil && !os.IsNotExist(e) {
		return e
	}
	if _, e = os.Stat(target); e == nil {
		if e = os.Rename(target, backup); e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	if e = os.Rename(next, target); e != nil {
		os.Rename(backup, target)
		return e
	}
	return nil
}
func (a *App) readTask(id string) (State, error) {
	var state State
	if !taskIDPattern.MatchString(id) {
		return state, errors.New("任务 ID 无效")
	}
	for _, suffix := range []string{".json", ".previous.json"} {
		data, e := os.ReadFile(filepath.Join(a.dir, "tasks", id+suffix))
		if e != nil {
			continue
		}
		if json.Unmarshal(data, &state) != nil || state.ID != id || state.SiteKind == "cf-vps" {
			continue
		}
		if normalizeTask(&state) == nil {
			return state, nil
		}
	}
	return State{}, errors.New("找不到有效的任务记录")
}
func (a *App) taskList() ([]TaskInfo, error) {
	out := []TaskInfo{}
	if !a.historyEnabled() {
		return out, nil
	}
	entries, e := os.ReadDir(filepath.Join(a.dir, "tasks"))
	if e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		id := strings.TrimSuffix(entry.Name(), ".json")
		if strings.HasSuffix(entry.Name(), ".previous.json") {
			id = strings.TrimSuffix(entry.Name(), ".previous.json")
		}
		if seen[id] {
			continue
		}
		if entry.IsDir() || !taskIDPattern.MatchString(id) {
			continue
		}
		var info TaskInfo
		data, e := os.ReadFile(filepath.Join(a.dir, "tasks", id+".meta.json"))
		if e != nil || json.Unmarshal(data, &info) != nil || info.ID != id {
			state, e := a.readTask(id)
			if e != nil {
				continue
			}
			info = taskInfo(state)
		}
		if info.Status == "running" || info.Status == "stopping" {
			info.Status = "paused"
		}
		out = append(out, info)
		seen[id] = true
	}
	a.mu.Lock()
	current := taskInfo(a.state)
	if a.state.SiteKind == "cf-vps" {
		current = TaskInfo{}
	}
	a.mu.Unlock()
	if current.ID != "" && current.Total > 0 {
		if seen[current.ID] {
			for i := range out {
				if out[i].ID == current.ID {
					out[i] = current
					break
				}
			}
		} else {
			out = append(out, current)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Created == out[j].Created {
			return out[i].ID > out[j].ID
		}
		return out[i].Created > out[j].Created
	})
	return out, nil
}

// The API serializes task mutations with controlMu. Save the outgoing task
// first; switching only changes which independent checkpoint is displayed.
func (a *App) selectTask(id string) error {
	if !a.historyEnabled() {
		return errors.New("此程序不支持 NCV 历史任务切换")
	}
	a.mu.Lock()
	busy := a.busyLocked()
	current := a.state
	a.mu.Unlock()
	if busy {
		return errors.New("请先暂停当前任务并等待进度保存")
	}
	next, e := a.readTask(id)
	if e != nil {
		return e
	}
	if e = a.save(); e != nil {
		return fmt.Errorf("当前任务保存失败，未切换：%w", e)
	}
	a.mu.Lock()
	a.state = next
	a.mu.Unlock()
	if e = a.save(); e != nil {
		a.mu.Lock()
		a.state = current
		a.mu.Unlock()
		return fmt.Errorf("任务切换保存失败：%w", e)
	}
	return nil
}
