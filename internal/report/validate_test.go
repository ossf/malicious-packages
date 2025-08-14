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
			{},
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
			},
		},
	}
	err := report.ValidateVuln(vuln)

	if err == nil {
		t.Error("ValidateVuln() == nil; want err")
	}
}

func TestValidateVuln_Fail_InvalidRange(t *testing.T) {
	tests := []struct {
		name string
		r    osvschema.Range
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
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			vuln := &osvschema.Vulnerability{
				Affected: []osvschema.Affected{
					{
						Package: osvschema.Package{
							Ecosystem: string(osvschema.EcosystemPyPI),
							Name:      "example",
						},
						Ranges: []osvschema.Range{test.r},
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
