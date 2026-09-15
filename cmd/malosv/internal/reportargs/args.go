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

import (
	"fmt"
	"log"
	"slices"
	"strings"

	"github.com/ossf/malicious-packages/internal/config"
)

// ReportArguments is an implementation of cli.Arguments used for parsing
// report arguments from the command line.
//
// Example:
//
//	var cfg config.Config
//
//	cli.Command{
//		Arguments: []cli.Argument{
//			&reportargs.ReportArguments{
//				Config: &cfg,
//				Resolvers: reportargs.AllResolvers,
//				BasesFn: func(cfg *config.Config) []string { return []string{cfg.MaliciousPath} },
//			},
//		},
//	}
type ReportArguments struct {
	// Config is the processed config. When this struct is created the Config has
	// not been processed, so this should point to where the parsed config will be
	// stored after it has been loaded.
	Config *config.Config

	// BasesFn returns the base paths for where the reports are located. This is
	// a function because at the time this struct is created the Config has not
	// been processed.
	BasesFn func(*config.Config) []string

	// Resolvers are the set of enabled resolvers. This is a bit-wise set of
	// ResolverFlags.
	//
	// Example:
	//
	//     ResolveArguments{
	//       Resolvers: ResolveByFile | ResolveByDirectory
	//     }
	//
	// Use AllResolvers if all the resolvers are desired.
	Resolvers ResolverFlags

	// IgnoreUnparsed will cause Parse to return any unprocessed arguments rather
	// than returning an error.
	IgnoreUnparsed bool

	// Reports is a map of the report path, and a slice of the
	// filenames of the OSV reports in that path. The report path is the
	// "ecosystem/package_name" fragment, and may include OSV filenames in
	// different base directories.
	reports map[string][]string
}

// Implements the cli.Argument interface.
//
// Always returns false.
func (a *ReportArguments) HasName(name string) bool {
	// We don't need a name.
	return false
}

// Implements the cli.Argument interface.
func (a *ReportArguments) Parse(args []string) ([]string, error) {
	bases := a.BasesFn(a.Config)

	a.reports = make(map[string][]string)

	// This loop steps through the resolver flags in r and checks if each is set.
	// The index i corresponds to each flag's bit position.
	for _, r := range resolvers {
		if !r.IsEnabled(a.Resolvers) {
			// Resolver is not enabled. So skip.
			continue
		}
		log.Printf("Resolving by %s...", r.name)

		reports, unused, err := r.Resolve(args, bases)
		if err != nil {
			return nil, fmt.Errorf("resolver %v failed: %w", r.name, err)
		}
		for key, paths := range reports {
			for _, path := range paths {
				if slices.Contains(a.reports[key], path) {
					return nil, fmt.Errorf("duplicate report specified: %q", path)
				}
			}
			a.reports[key] = append(a.reports[key], paths...)
		}
		args = unused
		if len(args) == 0 {
			break
		}
	}

	if !a.IgnoreUnparsed && len(args) > 0 {
		return nil, fmt.Errorf("failed to find reports: %v", args)
	}

	return args, nil
}

// Implements the cli.Argument interface.
func (a *ReportArguments) Usage() string {
	var parts []string
	for _, r := range resolvers {
		if !r.IsEnabled(a.Resolvers) {
			continue
		}
		parts = append(parts, r.argName)
	}
	argName := strings.Join(parts, "|")
	return fmt.Sprintf("<%s> [<%s> ...]", argName, argName)
}

func (a *ReportArguments) Reports() map[string][]string {
	if a == nil {
		return nil
	}
	return a.reports
}

// Implements the cli.Argument interface.
func (a *ReportArguments) Get() any {
	return a.Reports()
}
