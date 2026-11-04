//go:build !windows

package main

import "os/exec"

func prepareCommand(cmd *exec.Cmd)       {}
func attachProcess(cmd *exec.Cmd) func() { return func() {} }
func openBrowser(url string)             { exec.Command("xdg-open", url).Start() }
