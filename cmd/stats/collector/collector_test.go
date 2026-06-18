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

package collector_test

import (
	"reflect"
	"testing"

	"github.com/ossf/malicious-packages/cmd/stats/collector"
)

func TestNew(t *testing.T) {
	c := collector.New("test collector", "col1", "col2")
	if c == nil {
		t.Fatal("New() returned nil")
	}
	// Basic check for initialization. More detailed checks are in other tests.
	csv := c.ForCSV()
	if !reflect.DeepEqual(csv[0], []string{"col1", "col2", "test collector"}) {
		t.Errorf("ForCSV() header = %v, want %v", csv[0], []string{"col1", "col2", "test collector"})
	}
}

func TestInc(t *testing.T) {
	c := collector.New("test", "ecosystem", "date")
	c.Inc("npm", "2025-01-01")
	c.Inc("npm", "2025-01-01")
	c.Inc("pypi", "2025-01-01")
	c.Inc("npm", "2025-02-01")

	got := c.ForCSV()
	want := [][]string{
		{"ecosystem", "date", "test"},
		{"npm", "2025-01-01", "2"},
		{"npm", "2025-02-01", "1"},
		{"pypi", "2025-01-01", "1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ForCSV() = %v, want %v", got, want)
	}
}

func TestInc_Panic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()
	c := collector.New("test", "one_col")
	// Should panic because it expects 1 key but gets 2.
	c.Inc("key1", "key2")
}

func TestForCSV(t *testing.T) {
	c := collector.New("report counts", "ecosystem", "year")
	c.Inc("npm", "2024")
	c.Inc("pypi", "2025")
	c.Inc("npm", "2024")
	c.Inc("go", "2024")
	c.Inc("pypi", "2024")

	got := c.ForCSV()
	want := [][]string{
		{"ecosystem", "year", "report counts"},
		{"go", "2024", "1"},
		{"npm", "2024", "2"},
		{"pypi", "2024", "1"},
		{"pypi", "2025", "1"},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("ForCSV() got = %v, want %v", got, want)
	}
}

func TestForJSON(t *testing.T) {
	c := collector.New("counts", "ecosystem", "date")
	c.Inc("npm", "2025-01")
	c.Inc("npm", "2025-01")
	c.Inc("pypi", "2025-01")
	c.Inc("npm", "2025-02")
	c.Inc("go", "2025-03")

	got := c.ForJSON()
	want := map[string]any{
		"go": map[string]any{
			"2025-03": 1,
		},
		"npm": map[string]any{
			"2025-01": 2,
			"2025-02": 1,
		},
		"pypi": map[string]any{
			"2025-01": 1,
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("ForJSON() got = %v, want %v", got, want)
	}
}

func TestCollector_NoColumns(t *testing.T) {
	c := collector.New("total")
	c.Inc()
	c.Inc()
	c.Inc()

	gotCSV := c.ForCSV()
	wantCSV := [][]string{
		{"total"},
		{"3"},
	}
	if !reflect.DeepEqual(gotCSV, wantCSV) {
		t.Errorf("ForCSV() = %v, want %v", gotCSV, wantCSV)
	}

	gotJSON := c.ForJSON()
	wantJSON := 3
	if gotJSON != wantJSON {
		t.Errorf("ForJSON() = %v, want %v", gotJSON, wantJSON)
	}
}

func TestCollector_Empty(t *testing.T) {
	c := collector.New("empty", "col1")

	gotCSV := c.ForCSV()
	wantCSV := [][]string{
		{"col1", "empty"},
	}
	if !reflect.DeepEqual(gotCSV, wantCSV) {
		t.Errorf("ForCSV() = %v, want %v", gotCSV, wantCSV)
	}

	gotJSON := c.ForJSON()
	if gotJSON != nil {
		t.Errorf("ForJSON() = %v, want nil", gotJSON)
	}
}

func TestForJSON_SingleColumn(t *testing.T) {
	c := collector.New("counts", "ecosystem")
	c.Inc("npm")
	c.Inc("npm")
	c.Inc("pypi")

	got := c.ForJSON()
	want := map[string]any{
		"npm":  2,
		"pypi": 1,
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("ForJSON() got = %v, want %v", got, want)
	}
}
