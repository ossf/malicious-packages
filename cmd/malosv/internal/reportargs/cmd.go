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

package reportargs

import "github.com/urfave/cli/v3"

// FromCommand will return report arguments from cmd.
func FromCommand(cmd *cli.Command) map[string][]string {
	for _, arg := range cmd.Arguments {
		if reports, ok := arg.(*ReportArguments); ok {
			return reports.Reports()
		}
	}
	return nil
}
