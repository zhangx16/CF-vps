package main

import (
	"regexp"
	"strings"
)

var invalidFilename = regexp.MustCompile(`[\x00-\x1f\x7f<>:"/\\|?*]`)

func exportFilename(name, format string) string {
	name = strings.Trim(invalidFilename.ReplaceAllString(name, "_"), " .")
	runes := []rune(name)
	if len(runes) > 100 {
		name = string(runes[:100])
	}
	if name == "" {
		name = "测试结果"
	}
	ext := ".txt"
	if format == "csv" {
		ext = ".csv"
	}
	return name + ext
}
