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

package report_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvconstants"

	"github.com/ossf/malicious-packages/internal/report"
	mppb "github.com/ossf/malicious-packages/proto"
)

func TestIndicators_Valid(t *testing.T) {
	r := testReport(osvconstants.EcosystemPyPI, "example")
	r.DbSpecificVuln().DatabaseSpecific = mppb.DatabaseSpecific_builder{
		Iocs: mppb.Indicators_builder{
			Domains: []string{"example", "example.com", "this.is.an.example.com", "_service.at.example.com", "foo-bar.example.com", "g.co"},
			Ips:     []string{"127.0.0.1", "127.0.0.0/24", "2001:db8:a0b:12f0::1", "2001:db8:a0b:12f0::1/32"},
			Urls:    []string{"https://example.com", "emailto:person@example.com", "authority:"},
			Files: []*mppb.Indicators_File{
				mppb.Indicators_File_builder{
					Paths:  []string{"package/postinstall.js"},
					Source: mppb.Indicators_File_PACKAGE_ARCHIVE,
					Digests: &mppb.Indicators_File_Digests{
						Sha256: "BD13913906ED463642719633F36F04CF10AE6F9C9360FCDE842F8B6B1DAF0B02",
					},
				}.Build(),
				mppb.Indicators_File_builder{
					Paths:  []string{"/tmp/stage2.bin", "/var/tmp/stage2.bin"},
					Note:   "second stage dropped from a C2",
					Source: mppb.Indicators_File_DROPPED,
					Digests: &mppb.Indicators_File_Digests{
						Md5:    "D41D8CD98F00B204E9800998ECF8427E",
						Sha1:   "da39a3ee5e6b4b0d3255bfef95601890afd80709",
						Sha256: "987872707c668af0739f7d0193c1db906eb87e0749a5801a8a166a0aa2735136",
						Tlsh:   "T10123456789012345678901234567890123456789012345678901234567890123456789",
						Ssdeep: "12:AbCd+/12:XyZ",
					},
				}.Build(),
				mppb.Indicators_File_builder{
					Source: mppb.Indicators_File_IN_MEMORY,
					Note:   "decoded payload that never hit disk",
					Digests: &mppb.Indicators_File_Digests{
						Sha256: "0000000000000000000000000000000000000000000000000000000000000000",
					},
				}.Build(),
			},
		}.Build(),
	}.Build()

	if err := r.Validate(); err != nil {
		t.Fatalf("Validate() = %v; want nil", err)
	}
}

func TestIndicators_ValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		iocs *mppb.Indicators
	}{
		{
			name: "domain in ip",
			iocs: mppb.Indicators_builder{Ips: []string{"example.com"}}.Build(),
		},
		{
			name: "url in ip",
			iocs: mppb.Indicators_builder{Ips: []string{"https://example.com"}}.Build(),
		},
		{
			name: "invalid ip 1",
			iocs: mppb.Indicators_builder{Ips: []string{"127.0.1"}}.Build(),
		},
		{
			name: "invalid ip 2",
			iocs: mppb.Indicators_builder{Ips: []string{"127.0.0.0.1"}}.Build(),
		},
		{
			name: "invalid cidr 1",
			iocs: mppb.Indicators_builder{Ips: []string{"127.0.0.1//"}}.Build(),
		},
		{
			name: "invalid cidr 2",
			iocs: mppb.Indicators_builder{Ips: []string{"127.0.0.1/33"}}.Build(),
		},
		{
			name: "url in domain 1",
			iocs: mppb.Indicators_builder{Domains: []string{"https://example.com/"}}.Build(),
		},
		{
			name: "url in domain 2",
			iocs: mppb.Indicators_builder{Domains: []string{"example.com/path"}}.Build(),
		},
		{
			name: "ip in domain",
			iocs: mppb.Indicators_builder{Domains: []string{"127.0.0.1"}}.Build(),
		},
		{
			name: "invalid domain 1",
			iocs: mppb.Indicators_builder{Domains: []string{"💩"}}.Build(),
		},
		{
			name: "invalid domain 3",
			iocs: mppb.Indicators_builder{Domains: []string{"this.is.a.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.really.long.domain.example.com"}}.Build(),
		},
		{
			name: "invalid domain 4",
			iocs: mppb.Indicators_builder{Domains: []string{"this-is-a-really-really-really-really-really-really-really-really-really-long-label.example.com"}}.Build(),
		},
		{
			name: "invalid url",
			iocs: mppb.Indicators_builder{Urls: []string{"://domain"}}.Build(),
		},
		{
			name: "invalid file sha256",
			iocs: mppb.Indicators_builder{
				Files: []*mppb.Indicators_File{
					mppb.Indicators_File_builder{
						Paths:  []string{"x.js"},
						Source: mppb.Indicators_File_PACKAGE_ARCHIVE,
						Digests: &mppb.Indicators_File_Digests{
							Sha256: "not-a-hash",
						},
					}.Build(),
				},
			}.Build(),
		},
		{
			name: "invalid file md5",
			iocs: mppb.Indicators_builder{
				Files: []*mppb.Indicators_File{
					mppb.Indicators_File_builder{
						Paths:  []string{"x.js"},
						Source: mppb.Indicators_File_PACKAGE_ARCHIVE,
						Digests: &mppb.Indicators_File_Digests{
							Md5: "zz",
						},
					}.Build(),
				},
			}.Build(),
		},
		{
			name: "invalid file sha1",
			iocs: mppb.Indicators_builder{
				Files: []*mppb.Indicators_File{
					mppb.Indicators_File_builder{
						Paths:  []string{"x.js"},
						Source: mppb.Indicators_File_PACKAGE_ARCHIVE,
						Digests: &mppb.Indicators_File_Digests{
							Sha1: "zz",
						},
					}.Build(),
				},
			}.Build(),
		},
		{
			name: "invalid file tlsh",
			iocs: mppb.Indicators_builder{
				Files: []*mppb.Indicators_File{
					mppb.Indicators_File_builder{
						Paths:  []string{"x.js"},
						Source: mppb.Indicators_File_PACKAGE_ARCHIVE,
						Digests: &mppb.Indicators_File_Digests{
							Sha256: "987872707c668af0739f7d0193c1db906eb87e0749a5801a8a166a0aa2735136",
							Tlsh:   "xyz",
						},
					}.Build(),
				},
			}.Build(),
		},
		{
			name: "invalid file ssdeep",
			iocs: mppb.Indicators_builder{
				Files: []*mppb.Indicators_File{
					mppb.Indicators_File_builder{
						Paths:  []string{"x.js"},
						Source: mppb.Indicators_File_PACKAGE_ARCHIVE,
						Digests: &mppb.Indicators_File_Digests{
							Sha256: "987872707c668af0739f7d0193c1db906eb87e0749a5801a8a166a0aa2735136",
							Ssdeep: "notssdeep",
						},
					}.Build(),
				},
			}.Build(),
		},
		{
			name: "empty file entry",
			iocs: mppb.Indicators_builder{
				Files: []*mppb.Indicators_File{
					mppb.Indicators_File_builder{
						Note:   "no path and no digest",
						Source: mppb.Indicators_File_PACKAGE_ARCHIVE,
					}.Build(),
				},
			}.Build(),
		},
		{
			name: "file with only fuzzy digest",
			iocs: mppb.Indicators_builder{
				Files: []*mppb.Indicators_File{
					mppb.Indicators_File_builder{
						Source: mppb.Indicators_File_PACKAGE_ARCHIVE,
						Digests: &mppb.Indicators_File_Digests{
							Ssdeep: "12:AbCd+/12:XyZ",
						},
					}.Build(),
				},
			}.Build(),
		},
		{
			name: "file path too long",
			iocs: mppb.Indicators_builder{
				Files: []*mppb.Indicators_File{
					mppb.Indicators_File_builder{
						Paths:  []string{strings.Repeat("a", 1025)},
						Source: mppb.Indicators_File_PACKAGE_ARCHIVE,
						Digests: &mppb.Indicators_File_Digests{
							Sha256: "987872707c668af0739f7d0193c1db906eb87e0749a5801a8a166a0aa2735136",
						},
					}.Build(),
				},
			}.Build(),
		},
		{
			name: "file note too long",
			iocs: mppb.Indicators_builder{
				Files: []*mppb.Indicators_File{
					mppb.Indicators_File_builder{
						Paths:  []string{"x.js"},
						Note:   strings.Repeat("a", 513),
						Source: mppb.Indicators_File_PACKAGE_ARCHIVE,
						Digests: &mppb.Indicators_File_Digests{
							Sha256: "987872707c668af0739f7d0193c1db906eb87e0749a5801a8a166a0aa2735136",
						},
					}.Build(),
				},
			}.Build(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := testReport(osvconstants.EcosystemPyPI, "example")
			r.DbSpecificVuln().DatabaseSpecific = &mppb.DatabaseSpecific{Iocs: test.iocs}
			if err := r.Validate(); !errors.Is(err, report.ErrUnexpectedOSV) {
				t.Fatalf("Validate() = %v; want = %v", err, report.ErrUnexpectedOSV)
			}
		})
	}
}
