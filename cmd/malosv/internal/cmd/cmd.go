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

package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/ossf/malicious-packages/cmd/malosv/internal/reportargs"
	"github.com/ossf/malicious-packages/internal/config"
)

var Command *cli.Command

func init() {
	var cfg config.Config

	Command = &cli.Command{
		Name:  "malosv",
		Usage: "Manage the malicious packages repository",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Usage:   "Load configuration from `FILE`",
				Value:   "config/config.yaml",
			},
		},
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			configPath := cmd.String("config")
			configFile, err := os.Open(configPath)
			if err != nil {
				return ctx, fmt.Errorf("failed to open config file %s: %w", configPath, err)
			}
			defer configFile.Close()

			c, err := config.ReadYAML(configFile)
			if err != nil {
				return ctx, fmt.Errorf("failed reading config: %w", err)
			}
			log.Printf("Loaded config from %s", configPath)

			cfg = *c
			ctx = cfg.NewContext(ctx)
			return ctx, nil
		},
		Commands: []*cli.Command{
			{
				Name:   "withdraw",
				Usage:  "Withdraw one or more reports",
				Action: Withdraw,
				Arguments: []cli.Argument{
					&reportargs.ReportArguments{
						Config:    &cfg,
						Resolvers: reportargs.AllResolvers,
						BasesFn:   func(cfg *config.Config) []string { return []string{cfg.MaliciousPath} },
					},
				},
				Flags: []cli.Flag{
					&cli.TimestampFlag{
						Name: "withdraw-at",
						Config: cli.TimestampConfig{
							Layouts: []string{time.RFC3339},
						},
					},
				},
			},
			{
				Name:   "unwithdraw",
				Usage:  "Unwithdraw one or more reports",
				Action: Unwithdraw,
				Arguments: []cli.Argument{
					&reportargs.ReportArguments{
						Config:    &cfg,
						Resolvers: reportargs.AllResolvers,
						BasesFn:   func(cfg *config.Config) []string { return []string{cfg.FalsePositivePath} },
					},
				},
			},
		},
	}
}
