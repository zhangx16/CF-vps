package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const defaultProject = "cf-vps"

func (a *App) projectKind() string {
	if a.project != "" {
		return a.project
	}
	return defaultProject
}
func (a *App) skipTCP() bool { return a.projectKind() == "cf-vps" }

// Older unified builds kept CF tasks in the NCV folder. Copy only a CF task,
// without removing or overwriting either project's existing saved data.
func migrateCFState(dir string) { migrateCFStateFor(dir, defaultProject) }
func migrateCFStateFor(dir, project string) {
	if project != "cf-vps" {
		return
	}
	if _, e := os.Stat(filepath.Join(dir, "state.json")); e == nil {
		return
	}
	base, e := os.UserConfigDir()
	if e != nil {
		return
	}
	old := filepath.Join(base, "NCV-Desktop")
	for _, name := range []string{"state.json", "state.previous.json"} {
		data, e := os.ReadFile(filepath.Join(old, name))
		if e != nil {
			continue
		}
		var state State
		if json.Unmarshal(data, &state) != nil || state.SiteKind != "cf-vps" || len(state.Candidates) == 0 {
			continue
		}
		os.WriteFile(filepath.Join(dir, "state.json"), data, 0600)
		return
	}
}

func (a *App) prepareProfileState() {
	if !a.skipTCP() {
		return
	}
	a.state.Options.TCPConcurrency = 0
	if a.state.Status != "completed" {
		return
	}
	for _, ep := range a.state.Candidates {
		for ti := range a.state.Templates {
			if _, ok := a.state.Results[resultKey(ti, ep)]; !ok {
				a.state.Status = "paused"
				return
			}
		}
	}
}
