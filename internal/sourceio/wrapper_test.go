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
	"errors"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/ossf/malicious-packages/internal/sourceio"
)

func TestStorageWrapper_UnmarshalYAML_Valid(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		want     sourceio.Storage
	}{
		{
			name:     "none",
			contents: "type: ''",
		},
		{
			name:     "blob",
			contents: "type: blob\nbucket: gs://example/bucket\nlookback-entries: 10",
			want: &sourceio.BlobStorage{
				Bucket:          "gs://example/bucket",
				LookbackEntries: 10,
			},
		},
		{
			name:     "git",
			contents: "type: git\nrepository: https://example.com/repo.git\nbranch: notmain",
			want: &sourceio.GitStorage{
				Repository: "https://example.com/repo.git",
				Branch:     "notmain",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var s sourceio.StorageWrapper
			err := yaml.Unmarshal([]byte(test.contents), &s)
			if err != nil {
				t.Fatalf("Unmarshal() = %v; want no error", err)
			}
			got := s.Storage
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("Unmrashal() parsed %#v; want %#v", got, test.want)
			}
		})
	}
}

func TestStorageWrapper_UnmarshalYAML_Invalid(t *testing.T) {
	tests := []struct {
		name     string
		contents string
	}{
		{
			name:     "invalid",
			contents: "junk",
		},
		{
			name:     "unsupported type",
			contents: "type: unsupported",
		},
		{
			name:     "invalid blob",
			contents: "type: blob\nlookback-entries: six",
		},
		{
			name:     "invalid git",
			contents: "type: git\nbranch:\n  - 10",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var s sourceio.StorageWrapper
			err := yaml.Unmarshal([]byte(test.contents), &s)
			if !errors.Is(err, sourceio.ErrInvalidStorage) {
				t.Errorf("Unmarshal() = %v; want an %v error", err, sourceio.ErrInvalidStorage)
			}
		})
	}
}

func TestWrap(t *testing.T) {
	// This will fail to compile if StorageWrapper does not implement Storage.
	var s sourceio.Storage = sourceio.Wrap(&sourceio.GitStorage{})
	if got := s.StorageType(); got != sourceio.StorageTypeGit {
		t.Errorf("StorageType() = %q; want %q", got, sourceio.StorageTypeGit)
	}
}
