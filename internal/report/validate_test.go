package report_test

import (
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/ossf/malicious-packages/internal/report"
)

func TestValidateVuln_Valid(t *testing.T) {
	emptyStruct, _ := structpb.NewStruct(make(map[string]any))
	vuln := &osvschema.Vulnerability{
		Affected: []*osvschema.Affected{
			{
				Package: &osvschema.Package{
					Ecosystem: string(osvconstants.EcosystemDebian) + ":7",
					Name:      "example",
					Purl:      "pkg:deb/debian/example",
				},
				Ranges: []*osvschema.Range{
					{
						Type: osvschema.Range_ECOSYSTEM,
						Events: []*osvschema.Event{
							{Introduced: "0"},
							{Fixed: "1"},
						},
					},
				},
				Versions:          []string{"0", "0.1"},
				EcosystemSpecific: emptyStruct,
			},
		},
	}
	err := report.ValidateVuln(vuln)
	if err != nil {
		t.Errorf("ValidateVuln() = %v; want nil", err)
	}
}

func TestValidateVuln_Valid_SemVer(t *testing.T) {
	vuln := &osvschema.Vulnerability{
		Affected: []*osvschema.Affected{
			{
				Package: &osvschema.Package{
					Ecosystem: string(osvconstants.EcosystemCratesIO),
					Name:      "example",
				},
				Ranges: []*osvschema.Range{
					{
						Type: osvschema.Range_SEMVER,
						Events: []*osvschema.Event{
							{Introduced: "0"},
							{Fixed: "1.0.0"},
						},
					},
				},
			},
		},
	}
	err := report.ValidateVuln(vuln)
	if err != nil {
		t.Errorf("ValidateVuln() = %v; want nil", err)
	}
}

func TestValidateVuln_Valid_Git(t *testing.T) {
	vuln := &osvschema.Vulnerability{
		Affected: []*osvschema.Affected{
			{
				Versions: []string{"0.1.0"},
				Ranges: []*osvschema.Range{
					{
						Type: osvschema.Range_GIT,
						Events: []*osvschema.Event{
							{Introduced: "0"},
							{Fixed: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
						},
						Repo: "https://example.org/repo.git",
					},
					{
						Type: osvschema.Range_GIT,
						Events: []*osvschema.Event{
							{Introduced: "0"},
							{Fixed: "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
						},
						Repo: "https://example.org/repo.git",
					},
				},
			},
		},
	}
	err := report.ValidateVuln(vuln)
	if err != nil {
		t.Errorf("ValidateVuln() = %v; want nil", err)
	}
}

func TestValidateVuln_Fail_NoAffected(t *testing.T) {
	vuln := &osvschema.Vulnerability{}
	err := report.ValidateVuln(vuln)

	if err == nil {
		t.Error("ValidateVuln() == nil; want err")
	}
}

func TestValidateVuln_Fail_TwoAffected(t *testing.T) {
	vuln := &osvschema.Vulnerability{
		Affected: []*osvschema.Affected{
			{
				Package: &osvschema.Package{
					Ecosystem: string(osvconstants.EcosystemPyPI),
					Name:      "example1",
				},
			},
			{
				Package: &osvschema.Package{
					Ecosystem: string(osvconstants.EcosystemPyPI),
					Name:      "example2",
				},
			},
		},
	}
	err := report.ValidateVuln(vuln)

	if err == nil {
		t.Error("ValidateVuln() == nil; want err")
	}
}

func TestValidateVuln_Fail_NoPackage(t *testing.T) {
	vuln := &osvschema.Vulnerability{
		Affected: []*osvschema.Affected{
			{
				Versions: []string{"0"},
			},
		},
	}
	err := report.ValidateVuln(vuln)

	if err == nil {
		t.Error("ValidateVuln() == nil; want err")
	}
}

func TestValidateVuln_Fail_NoPackageName(t *testing.T) {
	vuln := &osvschema.Vulnerability{
		Affected: []*osvschema.Affected{
			{
				Package: &osvschema.Package{
					Ecosystem: string(osvconstants.EcosystemNPM),
				},
				Versions: []string{"0"},
			},
		},
	}
	err := report.ValidateVuln(vuln)

	if err == nil {
		t.Error("ValidateVuln() == nil; want err")
	}
}

func TestValidateVuln_Fail_PackageNameSpecialChars(t *testing.T) {
	vuln := &osvschema.Vulnerability{
		Affected: []*osvschema.Affected{
			{
				Package: &osvschema.Package{
					Ecosystem: string(osvconstants.EcosystemNPM),
					Name:      "exam\rple",
				},
				Versions: []string{"0"},
			},
		},
	}
	err := report.ValidateVuln(vuln)

	if err == nil {
		t.Error("ValidateVuln() == nil; want err")
	}
}

func TestValidateVuln_Fail_NoEcosystem(t *testing.T) {
	vuln := &osvschema.Vulnerability{
		Affected: []*osvschema.Affected{
			{
				Package: &osvschema.Package{
					Name: "example",
				},
				Versions: []string{"0"},
			},
		},
	}
	err := report.ValidateVuln(vuln)

	if err == nil {
		t.Error("ValidateVuln() == nil; want err")
	}
}

func TestValidateVuln_Fail_InvalidEcosystem(t *testing.T) {
	vuln := &osvschema.Vulnerability{
		Affected: []*osvschema.Affected{
			{
				Package: &osvschema.Package{
					Ecosystem: "pypi",
					Name:      "example",
				},
				Versions: []string{"0"},
			},
		},
	}
	err := report.ValidateVuln(vuln)

	if err == nil {
		t.Error("ValidateVuln() == nil; want err")
	}
}

//nolint:gocritic  // TODO: re-enable test after checking with Reversing Labs
func TestValidateVuln_Fail_NoVersionsOrRanges(t *testing.T) {
	//vuln := &osvschema.Vulnerability{
	//	Affected: []osvschema.Affected{
	//		{
	//			Package: osvschema.Package{
	//				Ecosystem: string(osvschema.EcosystemNPM),
	//				Name:      "example",
	//			},
	//		},
	//	},
	//}
	//err := report.ValidateVuln(vuln)
	//if err == nil {
	//	t.Error("ValidateVuln() == nil; want err")
	//}
}

func TestValidateVuln_Fail_InvalidRange(t *testing.T) {
	tests := []struct {
		name  string
		isGit bool
		r     *osvschema.Range
	}{
		{
			name: "empty",
		},
		{
			name: "unspecified type",
			r: &osvschema.Range{
				Type: osvschema.Range_UNSPECIFIED,
			},
		},
		{
			name: "invalid type",
			r: &osvschema.Range{
				Type: -1,
			},
		},
		{
			name: "invalid semver type",
			r: &osvschema.Range{
				Type: osvschema.Range_SEMVER,
				Events: []*osvschema.Event{
					{Introduced: "0"},
				},
			},
		},
		{
			name: "no events",
			r: &osvschema.Range{
				Type: osvschema.Range_ECOSYSTEM,
			},
		},
		{
			name: "empty event",
			r: &osvschema.Range{
				Type: osvschema.Range_ECOSYSTEM,
				Events: []*osvschema.Event{
					{},
				},
			},
		},
		{
			name: "invalid event 1",
			r: &osvschema.Range{
				Type: osvschema.Range_ECOSYSTEM,
				Events: []*osvschema.Event{
					{Introduced: "0", Fixed: "1"},
				},
			},
		},
		{
			name: "invalid event 2",
			r: &osvschema.Range{
				Type: osvschema.Range_ECOSYSTEM,
				Events: []*osvschema.Event{
					{Introduced: "0", LastAffected: "1"},
				},
			},
		},
		{
			name: "invalid event 3",
			r: &osvschema.Range{
				Type: osvschema.Range_GIT,
				Events: []*osvschema.Event{
					{Introduced: "0", Limit: "1"},
				},
			},
		},
		{
			name: "fixed and last affected",
			r: &osvschema.Range{
				Type: osvschema.Range_ECOSYSTEM,
				Events: []*osvschema.Event{
					{Introduced: "0"},
					{LastAffected: "1"},
					{Fixed: "2"},
				},
			},
		},
		{
			name: "git no repo",
			r: &osvschema.Range{
				Type: osvschema.Range_GIT,
				Events: []*osvschema.Event{
					{Introduced: "0"},
				},
			},
		},
		{
			name: "git invalid repo",
			r: &osvschema.Range{
				Type: osvschema.Range_GIT,
				Repo: ":",
				Events: []*osvschema.Event{
					{Introduced: "0"},
				},
			},
		},
		{
			name: "git non-hex commit id",
			r: &osvschema.Range{
				Type: osvschema.Range_GIT,
				Repo: "https://example.com/repo.git",
				Events: []*osvschema.Event{
					{Introduced: "this is not hex"},
				},
			},
		},
		{
			name: "git non-sha commit id",
			r: &osvschema.Range{
				Type: osvschema.Range_GIT,
				Repo: "https://example.com/repo.git",
				Events: []*osvschema.Event{
					{Introduced: "deadbeef"},
				},
			},
		},
		{
			name: "git zero commit",
			r: &osvschema.Range{
				Type: osvschema.Range_GIT,
				Repo: "https://example.com/repo.git",
				Events: []*osvschema.Event{
					{Introduced: "0"},
					{Fixed: "0"},
				},
			},
		},
		{
			name:  "git non-git type",
			isGit: true,
			r: &osvschema.Range{
				Type: osvschema.Range_ECOSYSTEM,
				Repo: "https://example.com/repo.git",
				Events: []*osvschema.Event{
					{Introduced: "0"},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var pkg *osvschema.Package
			if !test.isGit {
				pkg = &osvschema.Package{
					Ecosystem: string(osvconstants.EcosystemPyPI),
					Name:      "example",
				}
			}
			vuln := &osvschema.Vulnerability{
				Affected: []*osvschema.Affected{
					{
						Package: pkg,
						Ranges:  []*osvschema.Range{test.r},
					},
				},
			}
			err := report.ValidateVuln(vuln)
			if err == nil {
				t.Error("ValidateVuln() == nil; want err")
			}
		})
	}
}

func TestValidateVuln_Fail_DifferentRepos(t *testing.T) {
	vuln := &osvschema.Vulnerability{
		Affected: []*osvschema.Affected{
			{
				Ranges: []*osvschema.Range{
					{
						Type: osvschema.Range_GIT,
						Events: []*osvschema.Event{
							{Introduced: "0"},
						},
						Repo: "https://example.org/first.git",
					},
					{
						Type: osvschema.Range_GIT,
						Events: []*osvschema.Event{
							{Introduced: "0"},
						},
						Repo: "https://example.org/second.git",
					},
				},
			},
		},
	}
	err := report.ValidateVuln(vuln)
	if err == nil {
		t.Errorf("ValidateVuln() == nil; want err")
	}
}

func TestValidateVuln_Fail_InvalidPURLs(t *testing.T) {
	tests := []struct {
		name string
		p    *osvschema.Package
	}{
		{
			name: "purl parse error",
			p: &osvschema.Package{
				Ecosystem: string(osvconstants.EcosystemNPM),
				Name:      "example",
				Purl:      "not_a_purl",
			},
		},
		{
			name: "ecosystem mismatch 1",
			p: &osvschema.Package{
				Ecosystem: string(osvconstants.EcosystemNPM),
				Name:      "example",
				Purl:      "pkg:pypi/example",
			},
		},
		{
			name: "ecosystem mismatch 2",
			p: &osvschema.Package{
				Ecosystem: string(osvconstants.EcosystemNPM),
				Name:      "example",
				Purl:      "pkg:oci/example",
			},
		},
		{
			name: "name mismatch",
			p: &osvschema.Package{
				Ecosystem: string(osvconstants.EcosystemNPM),
				Name:      "example1",
				Purl:      "pkg:npm/example2",
			},
		},
		{
			name: "namespace mismatch 1",
			p: &osvschema.Package{
				Ecosystem: string(osvconstants.EcosystemNPM),
				Name:      "@org/example",
				Purl:      "pkg:npm/example",
			},
		},
		{
			name: "namespace mismatch 2",
			p: &osvschema.Package{
				Ecosystem: string(osvconstants.EcosystemNPM),
				Name:      "example",
				Purl:      "pkg:npm/%40org/example",
			},
		},
		{
			name: "namespace mismatch 3",
			p: &osvschema.Package{
				Ecosystem: string(osvconstants.EcosystemDebian) + ":7",
				Name:      "example",
				Purl:      "pkg:deb/notdebian/example",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			vuln := &osvschema.Vulnerability{
				Affected: []*osvschema.Affected{
					{
						Package:  test.p,
						Versions: []string{"0"},
					},
				},
			}
			err := report.ValidateVuln(vuln)
			if err == nil {
				t.Error("ValidateVuln() == nil; want err")
			}
		})
	}
}

func TestValidateVuln_Fail_EcosystemSpecific(t *testing.T) {
	ecosystemSpecific, _ := structpb.NewStruct(
		map[string]any{
			"test": "not empty",
		})
	vuln := &osvschema.Vulnerability{
		Affected: []*osvschema.Affected{
			{
				Package: &osvschema.Package{
					Ecosystem: string(osvconstants.EcosystemPyPI),
					Name:      "example",
				},
				EcosystemSpecific: ecosystemSpecific,
			},
		},
	}
	err := report.ValidateVuln(vuln)

	if err == nil {
		t.Error("ValidateVuln() == nil; want err")
	}
}
