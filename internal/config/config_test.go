// Copyright 2022 Malicious Packages Authors
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

package config_test

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"golang.org/x/exp/slices"

	"github.com/ossf/malicious-packages/internal/config"
	"github.com/ossf/malicious-packages/internal/source"
)

const validConfigYAML = `
id-prefix: TEST
malicious-path: "mal/"
false-positive-path: "false-positives/"
sources:
- id: all
  bucket: file://test-bucket/
  prefix: malicious
  lookback-entries: 123
- id: default
`

func TestReadYAML(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() = %v; want no error", err)
	}
	c, err := config.ReadYAML(bytes.NewBufferString(validConfigYAML))
	if err != nil {
		t.Fatalf("ReadYAML = %v; want no error", err)
	}
	if got, want := len(c.Sources), 2; got != want {
		t.Errorf("len(Sources) = %v; want %v", got, want)
	}
	if got, want := c.IDPrefix, "TEST"; got != want {
		t.Errorf("IDPrefix = %v; want %v", got, want)
	}
	if got, want := c.MaliciousPath, filepath.Join(wd, "mal"); got != want {
		t.Errorf("MaliciousPath = %v; want %v", got, want)
	}
	if got, want := c.FalsePositivePath, filepath.Join(wd, "false-positives"); got != want {
		t.Errorf("FalsePositivePath = %v; want %v", got, want)
	}
}

func TestReadYAML_Error(t *testing.T) {
	_, err := config.ReadYAML(bytes.NewBufferString(""))
	if err == nil {
		t.Fatal("ReadYAML = nil; want an error", err)
	}
}

func TestReadYAML_Invalid(t *testing.T) {
	_, err := config.ReadYAML(bytes.NewBufferString("sources: hello"))
	if err == nil {
		t.Fatal("ReadYAML = nil; want an error", err)
	}
}

func TestPaths(t *testing.T) {
	got := getTestConfig().Paths()
	want := []string{"./false/positives/", "./mal/path/"}
	sort.StringSlice(got).Sort() // Sort to eliminate any ordering issues.
	if !slices.Equal(got, want) {
		t.Errorf("c.Paths() = %v; want %v", got, want)
	}
}

func TestInit(t *testing.T) {
	if err := getTestConfig().Init(); err != nil {
		t.Errorf("Init() = %v; want no error", err)
	}
}

func TestInit_NoIDPrefix(t *testing.T) {
	c := getTestConfig()
	c.IDPrefix = ""
	if err := c.Init(); err == nil {
		t.Error("Init() = nil; want an error")
	}
}

func TestInit_NoMaliciousPath(t *testing.T) {
	c := getTestConfig()
	c.MaliciousPath = ""
	if err := c.Init(); err == nil {
		t.Error("Init() = nil; want an error")
	}
}

func TestInit_NoFalsePositivePath(t *testing.T) {
	c := getTestConfig()
	c.FalsePositivePath = ""
	if err := c.Init(); err == nil {
		t.Error("Init() = nil; want an error")
	}
}

func TestInit_NoSources(t *testing.T) {
	c := getTestConfig()
	c.Sources = make([]*source.Source, 0)
	if err := c.Init(); err == nil {
		t.Error("Init() = nil; want an error")
	}
}

func getTestConfig() *config.Config {
	return &config.Config{
		IDPrefix:          "FOO",
		MaliciousPath:     "./mal/path/",
		FalsePositivePath: "./false/positives/",
		Sources: []*source.Source{
			{
				ID: "source1",
			},
			{
				ID: "source2",
			},
		},
	}
}
