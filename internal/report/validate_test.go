package report_test

import (
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvschema"

	"github.com/ossf/malicious-packages/internal/report"
)

func TestValidateVuln_Valid(t *testing.T) {
	vuln := &osvschema.Vulnerability{
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{
					Ecosystem: string(osvschema.EcosystemDebian) + ":7",
					Name:      "example",
					Purl:      "pkg:deb/debian/example",
				},
				Ranges: []osvschema.Range{
					{
						Type: osvschema.RangeEcosystem,
						Events: []osvschema.Event{
							{Introduced: "0"},
							{Fixed: "1"},
						},
					},
				},
				Versions: []string{"0", "0.1"},
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
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{
					Ecosystem: string(osvschema.EcosystemCratesIO),
					Name:      "example",
				},
				Ranges: []osvschema.Range{
					{
						Type: osvschema.RangeSemVer,
						Events: []osvschema.Event{
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
		Affected: []osvschema.Affected{
			{
				Versions: []string{"0.1.0"},
				Ranges: []osvschema.Range{
					{
						Type: osvschema.RangeGit,
						Events: []osvschema.Event{
							{Introduced: "0"},
							{Fixed: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
						},
						Repo: "https://example.org/repo.git",
					},
					{
						Type: osvschema.RangeGit,
						Events: []osvschema.Event{
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
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{
					Ecosystem: string(osvschema.EcosystemPyPI),
					Name:      "example1",
				},
			},
			{
				Package: osvschema.Package{
					Ecosystem: string(osvschema.EcosystemPyPI),
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
		Affected: []osvschema.Affected{
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
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{
					Ecosystem: string(osvschema.EcosystemNPM),
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
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{
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
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{
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
		r     osvschema.Range
	}{
		{
			name: "empty",
		},
		{
			name: "invalid type",
			r: osvschema.Range{
				Type: "invalid",
			},
		},
		{
			name: "invalid semver type",
			r: osvschema.Range{
				Type: osvschema.RangeSemVer,
				Events: []osvschema.Event{
					{Introduced: "0"},
				},
			},
		},
		{
			name: "no events",
			r: osvschema.Range{
				Type: osvschema.RangeEcosystem,
			},
		},
		{
			name: "empty event",
			r: osvschema.Range{
				Type: osvschema.RangeEcosystem,
				Events: []osvschema.Event{
					{},
				},
			},
		},
		{
			name: "invalid event 1",
			r: osvschema.Range{
				Type: osvschema.RangeEcosystem,
				Events: []osvschema.Event{
					{Introduced: "0", Fixed: "1"},
				},
			},
		},
		{
			name: "invalid event 2",
			r: osvschema.Range{
				Type: osvschema.RangeEcosystem,
				Events: []osvschema.Event{
					{Introduced: "0", LastAffected: "1"},
				},
			},
		},
		{
			name: "invalid event 3",
			r: osvschema.Range{
				Type: osvschema.RangeGit,
				Events: []osvschema.Event{
					{Introduced: "0", Limit: "1"},
				},
			},
		},
		{
			name: "fixed and last affected",
			r: osvschema.Range{
				Type: osvschema.RangeEcosystem,
				Events: []osvschema.Event{
					{Introduced: "0"},
					{LastAffected: "1"},
					{Fixed: "2"},
				},
			},
		},
		{
			name: "git no repo",
			r: osvschema.Range{
				Type: osvschema.RangeGit,
				Events: []osvschema.Event{
					{Introduced: "0"},
				},
			},
		},
		{
			name: "git invalid repo",
			r: osvschema.Range{
				Type: osvschema.RangeGit,
				Repo: ":",
				Events: []osvschema.Event{
					{Introduced: "0"},
				},
			},
		},
		{
			name: "git non-hex commit id",
			r: osvschema.Range{
				Type: osvschema.RangeGit,
				Repo: "https://example.com/repo.git",
				Events: []osvschema.Event{
					{Introduced: "this is not hex"},
				},
			},
		},
		{
			name: "git non-sha commit id",
			r: osvschema.Range{
				Type: osvschema.RangeGit,
				Repo: "https://example.com/repo.git",
				Events: []osvschema.Event{
					{Introduced: "deadbeef"},
				},
			},
		},
		{
			name: "git zero commit",
			r: osvschema.Range{
				Type: osvschema.RangeGit,
				Repo: "https://example.com/repo.git",
				Events: []osvschema.Event{
					{Introduced: "0"},
					{Fixed: "0"},
				},
			},
		},
		{
			name:  "git non-git type",
			isGit: true,
			r: osvschema.Range{
				Type: osvschema.RangeEcosystem,
				Repo: "https://example.com/repo.git",
				Events: []osvschema.Event{
					{Introduced: "0"},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var pkg osvschema.Package
			if !test.isGit {
				pkg.Ecosystem = string(osvschema.EcosystemPyPI)
				pkg.Name = "example"
			}
			vuln := &osvschema.Vulnerability{
				Affected: []osvschema.Affected{
					{
						Package: pkg,
						Ranges:  []osvschema.Range{test.r},
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
		Affected: []osvschema.Affected{
			{
				Ranges: []osvschema.Range{
					{
						Type: osvschema.RangeGit,
						Events: []osvschema.Event{
							{Introduced: "0"},
						},
						Repo: "https://example.org/first.git",
					},
					{
						Type: osvschema.RangeGit,
						Events: []osvschema.Event{
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
		p    osvschema.Package
	}{
		{
			name: "purl parse error",
			p: osvschema.Package{
				Ecosystem: string(osvschema.EcosystemNPM),
				Name:      "example",
				Purl:      "not_a_purl",
			},
		},
		{
			name: "ecosystem mismatch 1",
			p: osvschema.Package{
				Ecosystem: string(osvschema.EcosystemNPM),
				Name:      "example",
				Purl:      "pkg:pypi/example",
			},
		},
		{
			name: "ecosystem mismatch 2",
			p: osvschema.Package{
				Ecosystem: string(osvschema.EcosystemNPM),
				Name:      "example",
				Purl:      "pkg:oci/example",
			},
		},
		{
			name: "name mismatch",
			p: osvschema.Package{
				Ecosystem: string(osvschema.EcosystemNPM),
				Name:      "example1",
				Purl:      "pkg:npm/example2",
			},
		},
		{
			name: "namespace mismatch 1",
			p: osvschema.Package{
				Ecosystem: string(osvschema.EcosystemNPM),
				Name:      "@org/example",
				Purl:      "pkg:npm/example",
			},
		},
		{
			name: "namespace mismatch 2",
			p: osvschema.Package{
				Ecosystem: string(osvschema.EcosystemNPM),
				Name:      "example",
				Purl:      "pkg:npm/%40org/example",
			},
		},
		{
			name: "namespace mismatch 2",
			p: osvschema.Package{
				Ecosystem: string(osvschema.EcosystemDebian) + ":7",
				Name:      "example",
				Purl:      "pkg:deb/notdebian/example",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			vuln := &osvschema.Vulnerability{
				Affected: []osvschema.Affected{
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
