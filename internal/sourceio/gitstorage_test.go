// Copyright 2025 Malicious Packages Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sourceio_test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/ossf/malicious-packages/internal/sourceio"
)

func TestGitStorage_Walk(t *testing.T) {
	dir := t.TempDir()

	w := initRepo(t, dir)

	files := map[string]string{
		"yes-file": "success",
		"no-file":  "fail",
	}
	commitHash := commitFilesToWorkTree(t, dir, files, w, "Initial files")

	s := &sourceio.GitStorage{
		Repository: dir,
		Branch:     "master",
	}
	if err := s.Open(t.Context()); err != nil {
		t.Fatalf("Open() = %v; want no error", err)
	}
	defer s.Close()
	prefix := "yes-"
	end, err := s.Walk(t.Context(), prefix, "", func(ctx context.Context, path string, r io.Reader) error {
		if !strings.HasPrefix(path, prefix) {
			t.Fatalf("path %q does not have prefix %q", path, prefix)
		}
		bytes, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("ReadAll() = %v; want no error", err)
		}
		if got := string(bytes); got != "success" {
			t.Fatalf("Read %q; want %q", got, "success")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Walk() = %v; want no error", err)
	}
	want := commitHash.String()
	if end != want {
		t.Fatalf("Walk() = %q; want %q", end, want)
	}
}

func TestGitStorage_Walk_WithStart(t *testing.T) {
	dir := t.TempDir()

	w := initRepo(t, dir)

	files := map[string]string{
		"yes-file1": "fail",
		"yes-file2": "success",
		"no-file1":  "fail",
	}
	baseHash := commitFilesToWorkTree(t, dir, files, w, "Initial files")

	files = map[string]string{
		"yes-file1": "success",
		"yes-file3": "success",
		"no-file2":  "fail",
	}
	commitHash := commitFilesToWorkTree(t, dir, files, w, "Updated files")

	s := &sourceio.GitStorage{
		Repository: dir,
		Branch:     "master",
	}
	if err := s.Open(t.Context()); err != nil {
		t.Fatalf("Open() = %v; want no error", err)
	}
	defer s.Close()
	prefix := "yes-"
	fileCount := 0
	wantFileCount := 2
	end, err := s.Walk(t.Context(), prefix, baseHash.String(), func(ctx context.Context, path string, r io.Reader) error {
		if !strings.HasPrefix(path, prefix) {
			t.Fatalf("path %q does not have prefix %q", path, prefix)
		}
		bytes, err := io.ReadAll(r)
		fileCount++
		if err != nil {
			t.Fatalf("ReadAll() = %v; want no error", err)
		}
		if got := string(bytes); got != "success" {
			t.Fatalf("Read %q; want %q", got, "success")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Walk() = %v; want no error", err)
	}
	want := commitHash.String()
	if end != want {
		t.Errorf("Walk() = %q; want %q", end, want)
	}
	if fileCount != wantFileCount {
		t.Errorf("%d files read; want %d files read", fileCount, wantFileCount)
	}
}

func initRepo(t *testing.T, dir string) *git.Worktree {
	t.Helper()
	r, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit() = %v; want no error", err)
	}

	w, err := r.Worktree()
	if err != nil {
		t.Fatalf("WorkTree() = %v; want no error", err)
	}
	return w
}

func commitFilesToWorkTree(t *testing.T, dir string, files map[string]string, w *git.Worktree, message string) plumbing.Hash {
	t.Helper()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("WriteFile(%q) = %v; want no error", name, err)
		}
		if _, err := w.Add(name); err != nil {
			t.Fatalf("Add(%q) = %v; want no error", name, err)
		}
	}
	hash, err := w.Commit(message, &git.CommitOptions{
		Author: &object.Signature{Name: "Test User", Email: "test@example.com", When: time.Now()},
	})
	if err != nil {
		t.Fatalf("Commit() = %v; want no error", err)
	}
	return hash
}
