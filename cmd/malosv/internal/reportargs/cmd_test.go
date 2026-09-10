// Copyright 2026 Malicious Packages Authors
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

package reportargs_test

import (
	"reflect"
	"testing"

	"github.com/urfave/cli/v3"

	"github.com/ossf/malicious-packages/cmd/malosv/internal/reportargs"
)

// A dummy argument that implements cli.Argument to test mixed argument lists.
type dummyArgument struct{}

func (d *dummyArgument) HasName(name string) bool              { return false }
func (d *dummyArgument) Parse(args []string) ([]string, error) { return args, nil }
func (d *dummyArgument) Usage() string                         { return "" }
func (d *dummyArgument) Get() any                              { return nil }

func TestFromCommand(t *testing.T) {
	reportsMap := map[string][]string{
		"npm/package": {"/path/to/report1.json"},
	}

	a := &reportargs.ReportArguments{}
	a.SetReportsForTesting(reportsMap)

	tests := []struct {
		name string
		cmd  *cli.Command
		want map[string][]string
	}{
		{
			name: "command with ReportArguments",
			cmd: &cli.Command{
				Arguments: []cli.Argument{
					&dummyArgument{},
					a,
				},
			},
			want: reportsMap,
		},
		{
			name: "command without ReportArguments",
			cmd: &cli.Command{
				Arguments: []cli.Argument{
					&dummyArgument{},
				},
			},
			want: nil,
		},
		{
			name: "command with empty arguments list",
			cmd: &cli.Command{
				Arguments: []cli.Argument{},
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := reportargs.FromCommand(tt.cmd)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FromCommand() = %v, want %v", got, tt.want)
			}
		})
	}
}
