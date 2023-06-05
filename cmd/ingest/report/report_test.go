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

package report_test

import (
	"testing"

	"github.com/ossf/malicious-packages/cmd/ingest/report"
)

func TestPath(t *testing.T) {
	tests := []struct {
		name      string
		ecosystem string
		want      string
	}{
		{
			name:      "github.com/ossf/malicious-packages/cmd/ingest",
			ecosystem: "Go",
			want:      "go/github.com/ossf/malicious-packages/cmd/ingest",
		},
		{
			name:      "ThIs-is-A-Package",
			ecosystem: "Github Action",
			want:      "github-action/this-is-a-package",
		},
		{
			name:      "././../../this/is-a_problematic/example/../.././",
			ecosystem: ".//.././.../ecosystem/../..././../",
			want:      "../this",
		},
	}
	for _, test := range tests {
		t.Run(test.ecosystem+" "+test.name, func(t *testing.T) {
			r := &report.Report{Name: test.name, Ecosystem: test.ecosystem}
			if got := r.Path(); got != test.want {
				t.Errorf("Dir() = %v; want %v", got, test.want)
			}
		})
	}
}
