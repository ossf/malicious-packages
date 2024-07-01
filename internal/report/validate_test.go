package report_test

import (
	"testing"

	"github.com/google/osv-scanner/pkg/models"

	"github.com/ossf/malicious-packages/internal/report"
)

func TestValidateVuln_Valid(t *testing.T) {
	vuln := &models.Vulnerability{
		Affected: []models.Affected{
			{
				Package: models.Package{
					Ecosystem: models.EcosystemDebian + ":7",
					Name:      "example",
					Purl:      "pkg:deb/debian/example",
				},
				Ranges: []models.Range{
					{
						Type: models.RangeEcosystem,
						Events: []models.Event{
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
	vuln := &models.Vulnerability{
		Affected: []models.Affected{
			{
				Package: models.Package{
					Ecosystem: models.EcosystemCratesIO,
					Name:      "example",
				},
				Ranges: []models.Range{
					{
						Type: models.RangeSemVer,
						Events: []models.Event{
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
	vuln := &models.Vulnerability{}
	err := report.ValidateVuln(vuln)

	if err == nil {
		t.Error("ValidateVuln() == nil; want err")
	}
}

func TestValidateVuln_Fail_TwoAffected(t *testing.T) {
	vuln := &models.Vulnerability{
		Affected: []models.Affected{
			{
				Package: models.Package{
					Ecosystem: models.EcosystemPyPI,
					Name:      "example1",
				},
			},
			{
				Package: models.Package{
					Ecosystem: models.EcosystemPyPI,
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
	vuln := &models.Vulnerability{
		Affected: []models.Affected{
			{},
		},
	}
	err := report.ValidateVuln(vuln)

	if err == nil {
		t.Error("ValidateVuln() == nil; want err")
	}
}

func TestValidateVuln_Fail_NoPackageName(t *testing.T) {
	vuln := &models.Vulnerability{
		Affected: []models.Affected{
			{
				Package: models.Package{
					Ecosystem: models.EcosystemNPM,
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
	vuln := &models.Vulnerability{
		Affected: []models.Affected{
			{
				Package: models.Package{
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
	vuln := &models.Vulnerability{
		Affected: []models.Affected{
			{
				Package: models.Package{
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
		r    models.Range
	}{
		{
			name: "empty",
		},
		{
			name: "invalid type",
			r: models.Range{
				Type: "invalid",
			},
		},
		{
			name: "invalid semver type",
			r: models.Range{
				Type: models.RangeSemVer,
				Events: []models.Event{
					{Introduced: "0"},
				},
			},
		},
		{
			name: "no events",
			r: models.Range{
				Type: models.RangeEcosystem,
			},
		},
		{
			name: "empty event",
			r: models.Range{
				Type: models.RangeEcosystem,
				Events: []models.Event{
					{},
				},
			},
		},
		{
			name: "invalid event 1",
			r: models.Range{
				Type: models.RangeEcosystem,
				Events: []models.Event{
					{Introduced: "0", Fixed: "1"},
				},
			},
		},
		{
			name: "invalid event 2",
			r: models.Range{
				Type: models.RangeEcosystem,
				Events: []models.Event{
					{Introduced: "0", LastAffected: "1"},
				},
			},
		},
		{
			name: "invalid event 3",
			r: models.Range{
				Type: models.RangeGit,
				Events: []models.Event{
					{Introduced: "0", Limit: "1"},
				},
			},
		},
		{
			name: "fixed and last affected",
			r: models.Range{
				Type: models.RangeEcosystem,
				Events: []models.Event{
					{Introduced: "0"},
					{LastAffected: "1"},
					{Fixed: "2"},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			vuln := &models.Vulnerability{
				Affected: []models.Affected{
					{
						Package: models.Package{
							Ecosystem: models.EcosystemPyPI,
							Name:      "example",
						},
						Ranges: []models.Range{test.r},
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
		p    models.Package
	}{
		{
			name: "purl parse error",
			p: models.Package{
				Ecosystem: models.EcosystemNPM,
				Name:      "example",
				Purl:      "not_a_purl",
			},
		},
		{
			name: "ecosystem mismatch",
			p: models.Package{
				Ecosystem: models.EcosystemNPM,
				Name:      "example",
				Purl:      "pkg:pypi/example",
			},
		},
		{
			name: "name mismatch",
			p: models.Package{
				Ecosystem: models.EcosystemNPM,
				Name:      "example1",
				Purl:      "pkg:npm/example2",
			},
		},
		{
			name: "namespace mismatch 1",
			p: models.Package{
				Ecosystem: models.EcosystemNPM,
				Name:      "@org/example",
				Purl:      "pkg:npm/example",
			},
		},
		{
			name: "namespace mismatch 2",
			p: models.Package{
				Ecosystem: models.EcosystemNPM,
				Name:      "example",
				Purl:      "pkg:npm/%40org/example",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			vuln := &models.Vulnerability{
				Affected: []models.Affected{
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
