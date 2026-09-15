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
	"github.com/ossf/malicious-packages/internal/report"
	"github.com/ossf/malicious-packages/internal/reportio"
)

// Withdraw will safely withdraw the reports specified on the command line.
func Withdraw(ctx context.Context, cmd *cli.Command) error {
	c := config.FromContext(ctx)
	reports := reportargs.FromCommand(cmd)

	// Ensure there is only one report per path
	var targets []string
	for path, pkgReports := range reports {
		if len(pkgReports) != 1 {
			return fmt.Errorf("too many reports for %q (%d)", path, len(pkgReports))
		}
		targets = append(targets, pkgReports...)
	}

	log.Printf("Found %d target(s) for withdrawal", len(targets))

	// Determine the withdrawal time.
	withdrawnTime := time.Now().UTC()
	if cmd.IsSet("withdraw-at") {
		withdrawnTime = cmd.Timestamp("withdraw-at").UTC()
	}

	log.Printf("Withdrawn time: %s", withdrawnTime.Format(time.RFC3339))

	// Create a temp directory for atomic writes. We use the system temp
	// directory to avoid accidentally leaving temp junk in the repository.
	tempDir, err := os.MkdirTemp("", "osv-withdraw-*")
	if err != nil {
		log.Fatalf("Failed creating temp dir: %v", err)
	}
	defer func() {
		// Clean up temp directory
		if err := os.RemoveAll(tempDir); err != nil {
			log.Fatalf("Failed cleaning up temp dir: %v", err)
		}
	}()

	for _, target := range targets {
		log.Printf("Withdrawing %s", target)

		// Change the report to include the withdrawn timestamp.
		if err := reportio.MutateReport(target, func(r *report.Report) (bool, error) {
			r.Withdraw(withdrawnTime)
			return true, nil
		}, tempDir); err != nil {
			return fmt.Errorf("failed to update report %s: %w", target, err)
		}

		// Move the report to the correct location for withdrawn reports.
		if err := reportio.MoveReport(target, c.MaliciousPath, c.FalsePositivePath); err != nil {
			return fmt.Errorf("failed to move report %s: %w", target, err)
		}
	}

	log.Printf("Successfully withdrew %d report(s)", len(targets))
	return nil
}
