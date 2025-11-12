// Copyright 2023 Malicious Packages Authors
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

//nolint:goconst
package sourceio_test

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "gocloud.dev/blob/fileblob"

	"github.com/ossf/malicious-packages/internal/sourceio"
)

func TestBlobStorage_Walk(t *testing.T) {
	dir := t.TempDir()

	fd1, err := os.Create(filepath.Join(dir, "yes-file"))
	if err != nil {
		t.Fatalf("Create() = %v; want no error", err)
	}
	fmt.Fprintf(fd1, "success")
	fd1.Close()

	fd2, err := os.Create(filepath.Join(dir, "no-file"))
	if err != nil {
		t.Fatalf("Create() = %v; want no error", err)
	}
	fmt.Fprintf(fd2, "fail")
	fd2.Close()

	s := &sourceio.BlobStorage{
		Bucket: "file://" + dir,
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
	if end != "" {
		t.Fatalf("Walk() = %q; want ''", end)
	}
}

func TestBlobStorage_Walk_Empty(t *testing.T) {
	dir := t.TempDir()

	s := &sourceio.BlobStorage{
		Bucket: "file://" + dir,
	}
	if err := s.Open(t.Context()); err != nil {
		t.Fatalf("Open() = %v; want no error", err)
	}
	defer s.Close()
	end, err := s.Walk(t.Context(), "", "", func(ctx context.Context, path string, r io.Reader) error {
		t.Fatalf("WalkFn() called; want no call")
		return nil
	})
	if err != nil {
		t.Fatalf("Walk() = %v; want no error", err)
	}
	if end != "" {
		t.Fatalf("Walk() = %q; want ''", end)
	}
}

func TestBlobStorage_Walk_NoBucket(t *testing.T) {
	s := &sourceio.BlobStorage{}
	if err := s.Open(t.Context()); err != nil {
		t.Fatalf("Open() = %v; want no error", err)
	}
	defer s.Close()
	end, err := s.Walk(t.Context(), "", "", func(ctx context.Context, path string, r io.Reader) error {
		t.Fatalf("WalkFn() called; want no call")
		return nil
	})
	if err != nil {
		t.Fatalf("Walk() = %v; want no error", err)
	}
	if end != "" {
		t.Fatalf("Walk() = %q; want ''", end)
	}
}
