package covreport

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/cover"
)

func TestClassifyBlock(t *testing.T) {
	tests := []struct {
		name   string
		counts map[string]int
		want   CoverageType
	}{
		{"uncovered", map[string]int{"unit": 0, "integration": 0}, Uncovered},
		{"unit only", map[string]int{"unit": 3, "integration": 0}, Unit},
		{"integration only", map[string]int{"unit": 0, "integration": 5}, Integration},
		{"both", map[string]int{"unit": 1, "integration": 2}, Both},
		{"single unit", map[string]int{"unit": 1}, Unit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyBlock(tt.counts)
			if got != tt.want {
				t.Errorf("classifyBlock(%v) = %d, want %d", tt.counts, got, tt.want)
			}
		})
	}
}

func TestBlockTitle(t *testing.T) {
	tests := []struct {
		name   string
		counts map[string]int
		want   string
	}{
		{"uncovered", map[string]int{"unit": 0}, "not covered"},
		{"unit only", map[string]int{"unit": 3}, "unit: 3x"},
		{"both", map[string]int{"integration": 2, "unit": 1}, "integration: 2x, unit: 1x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := blockTitle(tt.counts)
			if got != tt.want {
				t.Errorf("blockTitle(%v) = %q, want %q", tt.counts, got, tt.want)
			}
		})
	}
}

func TestFileID(t *testing.T) {
	got := fileID("github.com/foo/bar/pkg/file.go")
	if strings.ContainsAny(got, "/.") {
		t.Errorf("fileID should not contain / or .: got %q", got)
	}
	if !strings.HasPrefix(got, "file-") {
		t.Errorf("fileID should start with 'file-': got %q", got)
	}
}

func TestGenerateFromParsed(t *testing.T) {
	// Create a temp source file that matches the coverage profile path.
	dir := t.TempDir()
	srcFile := filepath.Join(dir, "example.go")
	if err := os.WriteFile(srcFile, []byte("package example\n\nfunc Hello() string {\n\treturn \"hello\"\n}\n\nfunc Unused() {\n\tpanic(\"unused\")\n}\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Build synthetic profiles using the temp file path.
	unitProfiles := []*cover.Profile{
		{
			FileName: srcFile,
			Mode:     "atomic",
			Blocks: []cover.ProfileBlock{
				{StartLine: 3, StartCol: 1, EndLine: 5, EndCol: 2, NumStmt: 1, Count: 3},
				{StartLine: 7, StartCol: 1, EndLine: 9, EndCol: 2, NumStmt: 1, Count: 0},
			},
		},
	}
	integrationProfiles := []*cover.Profile{
		{
			FileName: srcFile,
			Mode:     "atomic",
			Blocks: []cover.ProfileBlock{
				{StartLine: 3, StartCol: 1, EndLine: 5, EndCol: 2, NumStmt: 1, Count: 1},
				{StartLine: 7, StartCol: 1, EndLine: 9, EndCol: 2, NumStmt: 1, Count: 0},
			},
		},
	}

	allProfiles := map[string][]*cover.Profile{
		"unit":        unitProfiles,
		"integration": integrationProfiles,
	}

	var buf bytes.Buffer
	if err := GenerateFromParsed(&buf, allProfiles); err != nil {
		t.Fatalf("GenerateFromParsed() error: %v", err)
	}

	html := buf.String()

	// Verify basic structure.
	if !strings.Contains(html, "Coverage Report") {
		t.Error("missing title")
	}
	if !strings.Contains(html, "cov-both") {
		t.Error("expected 'cov-both' class for lines covered by both")
	}
	if !strings.Contains(html, "cov-none") {
		t.Error("expected 'cov-none' class for uncovered lines")
	}
	if !strings.Contains(html, "Unit") {
		t.Error("expected legend entry for Unit")
	}
	if !strings.Contains(html, "Integration") {
		t.Error("expected legend entry for Integration")
	}
	if !strings.Contains(html, "Total") {
		t.Error("expected Total in summary")
	}
}

func TestGenerateFromParsedUnitOnly(t *testing.T) {
	dir := t.TempDir()
	srcFile := filepath.Join(dir, "example.go")
	if err := os.WriteFile(srcFile, []byte("package example\n\nfunc Foo() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}

	allProfiles := map[string][]*cover.Profile{
		"unit": {
			{
				FileName: srcFile,
				Mode:     "atomic",
				Blocks: []cover.ProfileBlock{
					{StartLine: 3, StartCol: 1, EndLine: 3, EndCol: 15, NumStmt: 1, Count: 2},
				},
			},
		},
	}

	var buf bytes.Buffer
	if err := GenerateFromParsed(&buf, allProfiles); err != nil {
		t.Fatalf("GenerateFromParsed() error: %v", err)
	}

	html := buf.String()
	if !strings.Contains(html, "cov-unit") {
		t.Error("expected 'cov-unit' class for unit-only coverage")
	}
}

func TestDirectorySummaries(t *testing.T) {
	dir := t.TempDir()

	// Create two files in different subdirectories.
	pkgA := filepath.Join(dir, "a")
	pkgB := filepath.Join(dir, "b")
	os.MkdirAll(pkgA, 0755)
	os.MkdirAll(pkgB, 0755)

	fileA := filepath.Join(pkgA, "a.go")
	fileB := filepath.Join(pkgB, "b.go")
	os.WriteFile(fileA, []byte("package a\n\nfunc A() {}\n"), 0644)
	os.WriteFile(fileB, []byte("package b\n\nfunc B() {}\n"), 0644)

	allProfiles := map[string][]*cover.Profile{
		"unit": {
			{
				FileName: fileA,
				Mode:     "atomic",
				Blocks: []cover.ProfileBlock{
					{StartLine: 3, StartCol: 1, EndLine: 3, EndCol: 14, NumStmt: 1, Count: 5},
				},
			},
			{
				FileName: fileB,
				Mode:     "atomic",
				Blocks: []cover.ProfileBlock{
					{StartLine: 3, StartCol: 1, EndLine: 3, EndCol: 14, NumStmt: 1, Count: 0},
				},
			},
		},
	}

	var buf bytes.Buffer
	if err := GenerateFromParsed(&buf, allProfiles); err != nil {
		t.Fatalf("GenerateFromParsed() error: %v", err)
	}

	output := buf.String()

	// Should contain directory summary sections.
	if !strings.Contains(output, "dir-summary") {
		t.Error("expected dir-summary class in output")
	}
	// Should contain the sidebar tree with directory entries.
	if !strings.Contains(output, "tree-item") {
		t.Error("expected tree-item class in sidebar")
	}
	// Should have coverage bar elements.
	if !strings.Contains(output, "cov-bar") {
		t.Error("expected cov-bar class in directory summary")
	}
	// Directory for pkgA parent should exist.
	parentDir := dir
	if !strings.Contains(output, dirID(parentDir)) {
		t.Errorf("expected directory ID %q in output", dirID(parentDir))
	}
}

func TestHighlightGoSource(t *testing.T) {
	src := []byte(`package main

import "fmt"

// Hello returns a greeting.
func Hello() string {
	return "hello"
}
`)
	lines := highlightGoSource(src)

	joined := ""
	for _, l := range lines {
		joined += string(l) + "\n"
	}

	// Keywords should be highlighted.
	if !strings.Contains(joined, `syn-kw`) {
		t.Error("expected keyword highlighting (syn-kw)")
	}
	// Strings should be highlighted.
	if !strings.Contains(joined, `syn-str`) {
		t.Error("expected string highlighting (syn-str)")
	}
	// Comments should be highlighted.
	if !strings.Contains(joined, `syn-cmt`) {
		t.Error("expected comment highlighting (syn-cmt)")
	}
	// Quotes should be properly escaped (not double-escaped).
	if strings.Contains(joined, `&amp;`) {
		t.Error("found double-escaped HTML entity (&amp;)")
	}
	// The literal quote should appear as &quot; or &#34; exactly once per string,
	// not as &amp;quot; or &amp;#34;.
	if strings.Contains(joined, `&#34;`) {
		// This is correct single-escaping — but let's make sure no double escape.
		if strings.Contains(joined, `&amp;#34;`) {
			t.Error("found double-escaped &#34;")
		}
	}
}

func TestNoDoubleEscaping(t *testing.T) {
	dir := t.TempDir()
	srcFile := filepath.Join(dir, "main.go")
	os.WriteFile(srcFile, []byte("package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Println(\"hello\")\n}\n"), 0644)

	allProfiles := map[string][]*cover.Profile{
		"unit": {
			{
				FileName: srcFile,
				Mode:     "atomic",
				Blocks: []cover.ProfileBlock{
					{StartLine: 5, StartCol: 1, EndLine: 7, EndCol: 2, NumStmt: 1, Count: 1},
				},
			},
		},
	}

	var buf bytes.Buffer
	if err := GenerateFromParsed(&buf, allProfiles); err != nil {
		t.Fatalf("GenerateFromParsed() error: %v", err)
	}

	output := buf.String()
	if strings.Contains(output, "&amp;#34;") {
		t.Error("double-escaped quotes found in output")
	}
	if strings.Contains(output, "&#34;") {
		// Quotes inside syntax spans should use &quot; from html.EscapeString,
		// but should never be double-escaped.
		if strings.Contains(output, "&amp;quot;") {
			t.Error("double-escaped &quot; found in output")
		}
	}
}
