package report_test

import (
	"errors"
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

func TestValidateVuln_DatabaseSpecific(t *testing.T) {
	emptyStruct, err := structpb.NewStruct(map[string]any{})
	if err != nil {
		t.Fatalf("failed to create empty struct: %v", err)
	}

	cwesStruct, _ := structpb.NewStruct(map[string]any{"cwes": []any{"CWE-506"}})
	indicatorsStruct, _ := structpb.NewStruct(map[string]any{"indicators": []any{}})
	iocsStruct, _ := structpb.NewStruct(map[string]any{"iocs": map[string]any{}})
	ghsaStruct, _ := structpb.NewStruct(map[string]any{"ghsa": "GHSA-1234-5678-9012"})
	allAffectedStruct, _ := structpb.NewStruct(map[string]any{
		"cwes":       []any{"CWE-506"},
		"indicators": []any{},
		"iocs":       map[string]any{},
		"ghsa":       "GHSA-1234-5678-9012",
	})

	originsStruct, _ := structpb.NewStruct(map[string]any{"malicious-packages-origins": []any{}})
	allTopLevelStruct, _ := structpb.NewStruct(map[string]any{
		"malicious-packages-origins": []any{},
		"iocs":                       map[string]any{},
	})

	invalidKeyStruct, _ := structpb.NewStruct(map[string]any{"unexpected_custom_key": "custom_value"})
	mixedInvalidStruct, _ := structpb.NewStruct(map[string]any{
		"cwes":       []any{"CWE-506"},
		"unexpected": true,
	})

	tests := []struct {
		name     string
		affected *structpb.Struct
		top      *structpb.Struct
		wantErr  bool
	}{
		{
			name: "nil database_specific",
		},
		{
			name:     "empty database_specific",
			affected: emptyStruct,
			top:      emptyStruct,
		},
		{
			name:     "valid affected cwes",
			affected: cwesStruct,
		},
		{
			name:     "valid affected indicators",
			affected: indicatorsStruct,
		},
		{
			name:     "valid affected iocs",
			affected: iocsStruct,
		},
		{
			name:     "valid affected ghsa",
			affected: ghsaStruct,
		},
		{
			name:     "all valid affected keys combined",
			affected: allAffectedStruct,
		},
		{
			name: "valid top-level malicious-packages-origins",
			top:  originsStruct,
		},
		{
			name: "valid top-level iocs",
			top:  iocsStruct,
		},
		{
			name: "all valid top-level keys combined",
			top:  allTopLevelStruct,
		},
		{
			name:     "invalid affected key (malicious-packages-origins is top-level only)",
			affected: originsStruct,
			wantErr:  true,
		},
		{
			name:     "invalid affected key (unknown custom key)",
			affected: invalidKeyStruct,
			wantErr:  true,
		},
		{
			name:     "invalid affected keys (mixed valid and invalid)",
			affected: mixedInvalidStruct,
			wantErr:  true,
		},
		{
			name:    "invalid top-level key (cwes is affected-level only)",
			top:     cwesStruct,
			wantErr: true,
		},
		{
			name:    "invalid top-level key (indicators is affected-level only)",
			top:     indicatorsStruct,
			wantErr: true,
		},
		{
			name:    "invalid top-level key (ghsa is affected-level only)",
			top:     ghsaStruct,
			wantErr: true,
		},
		{
			name:    "invalid top-level key (unknown custom key)",
			top:     invalidKeyStruct,
			wantErr: true,
		},
		{
			name:    "invalid top-level keys (mixed valid and invalid)",
			top:     mixedInvalidStruct,
			wantErr: true,
		},
		{
			name:     "valid combined affected and top-level database_specific",
			affected: allAffectedStruct,
			top:      allTopLevelStruct,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vuln := &osvschema.Vulnerability{
				DatabaseSpecific: tt.top,
				Affected: []*osvschema.Affected{
					{
						Package: &osvschema.Package{
							Ecosystem: string(osvconstants.EcosystemPyPI),
							Name:      "example",
						},
						Versions:         []string{"0.0.1"},
						DatabaseSpecific: tt.affected,
					},
				},
			}
			err := report.ValidateVuln(vuln)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateVuln() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && !errors.Is(err, report.ErrUnexpectedOSV) {
				t.Errorf("ValidateVuln() error = %v; want error wrapping ErrUnexpectedOSV", err)
			}
		})
	}
}

func TestValidateVuln_GitHubActions_PackageName(t *testing.T) {
	tests := []struct {
		name    string
		pkgName string
		wantErr bool
	}{
		{
			name:    "valid standard owner/repo",
			pkgName: "actions/checkout",
			wantErr: false,
		},
		{
			name:    "valid owner/repo with subpath",
			pkgName: "actions/checkout/subaction",
			wantErr: false,
		},
		{
			name:    "invalid owner/repo with .git suffix",
			pkgName: "actions/checkout.git",
			wantErr: true,
		},
		{
			name:    "invalid owner/repo with .git suffix and subpath",
			pkgName: "actions/checkout.git/subaction",
			wantErr: true,
		},
		{
			name:    "valid mixed-case org and repo",
			pkgName: "Actions/CheckOut",
			wantErr: false,
		},
		{
			name:    "valid mixed-case org, repo and subpath",
			pkgName: "Actions/CheckOut/SubAction",
			wantErr: false,
		},
		{
			name:    "invalid single component",
			pkgName: "checkout",
			wantErr: true,
		},
		{
			name:    "invalid url scheme https",
			pkgName: "https://github.com/actions/checkout",
			wantErr: true,
		},
		{
			name:    "invalid url scheme http",
			pkgName: "http://github.com/actions/checkout",
			wantErr: true,
		},
		{
			name:    "invalid url scheme git@",
			pkgName: "git@github.com:actions/checkout",
			wantErr: true,
		},
		{
			name:    "invalid url scheme git://",
			pkgName: "git://github.com/actions/checkout",
			wantErr: true,
		},
		{
			name:    "invalid path traversal with .. in middle",
			pkgName: "actions/../checkout",
			wantErr: true,
		},
		{
			name:    "invalid path traversal with leading ..",
			pkgName: "../actions/checkout",
			wantErr: true,
		},
		{
			name:    "invalid path traversal with trailing ..",
			pkgName: "actions/checkout/..",
			wantErr: true,
		},
		{
			name:    "invalid path segment with .",
			pkgName: "actions/./checkout",
			wantErr: true,
		},
		{
			name:    "invalid empty segment double slash",
			pkgName: "actions//checkout",
			wantErr: true,
		},
		{
			name:    "invalid leading slash",
			pkgName: "/actions/checkout",
			wantErr: true,
		},
		{
			name:    "invalid trailing slash",
			pkgName: "actions/checkout/",
			wantErr: true,
		},
		{
			name:    "invalid whitespace leading",
			pkgName: " actions/checkout",
			wantErr: true,
		},
		{
			name:    "invalid whitespace trailing",
			pkgName: "actions/checkout ",
			wantErr: true,
		},
		{
			name:    "invalid whitespace middle",
			pkgName: "actions/ check out",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			vuln := &osvschema.Vulnerability{
				Affected: []*osvschema.Affected{
					{
						Package: &osvschema.Package{
							Ecosystem: string(osvconstants.EcosystemGitHubActions),
							Name:      tt.pkgName,
						},
						Versions: []string{"1.0.0"},
					},
				},
			}
			err := report.ValidateVuln(vuln)
			if tt.wantErr {
				if !errors.Is(err, report.ErrInvalidOSV) {
					t.Errorf("ValidateVuln() error = %v; want error wrapping ErrInvalidOSV", err)
				}
			} else if err != nil {
				t.Errorf("ValidateVuln() unexpected error = %v", err)
			}
		})
	}
}

func TestValidateVuln_GitHubActions_Versions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		versions []string
		wantErr  bool
	}{
		// Valid exact release tags
		{
			name:     "valid exact tag with v prefix",
			versions: []string{"v1.0.0"},
			wantErr:  false,
		},
		{
			name:     "valid exact tag without v prefix",
			versions: []string{"1.0.0"},
			wantErr:  false,
		},
		{
			name:     "valid exact tag v4.0.1",
			versions: []string{"v4.0.1"},
			wantErr:  false,
		},
		{
			name:     "valid exact tag 4.0.1",
			versions: []string{"4.0.1"},
			wantErr:  false,
		},
		{
			name:     "valid exact tag prerelease rc",
			versions: []string{"1.0.0-rc1"},
			wantErr:  false,
		},
		{
			name:     "valid exact tag prerelease beta",
			versions: []string{"v2.0.0-beta.2"},
			wantErr:  false,
		},
		{
			name:     "valid exact release label",
			versions: []string{"release-2026.01"},
			wantErr:  false,
		},
		{
			name:     "valid multiple exact tags",
			versions: []string{"v1.0.0", "v1.0.1", "v1.0.2"},
			wantErr:  false,
		},
		{
			name:     "valid two-digit tag v4.1",
			versions: []string{"v4.1"},
			wantErr:  false,
		},
		{
			name:     "valid two-digit tag 4.1",
			versions: []string{"4.1"},
			wantErr:  false,
		},
		{
			name:     "valid two-digit tag v1.0",
			versions: []string{"v1.0"},
			wantErr:  false,
		},
		{
			name:     "valid two-digit tag 1.0",
			versions: []string{"1.0"},
			wantErr:  false,
		},

		// Valid Git commit SHAs
		{
			name:     "valid 40-character commit sha lowercase",
			versions: []string{"11bd71901bbe5b1630ceea73d27597364c9af683"},
			wantErr:  false,
		},
		{
			name:     "valid 40-character commit sha another",
			versions: []string{"b4ffde65f46336ab88eb53be808477a3936bae11"},
			wantErr:  false,
		},
		{
			name:     "valid 40-character commit sha uppercase",
			versions: []string{"B4FFDE65F46336AB88EB53BE808477A3936BAE11"},
			wantErr:  false,
		},
		{
			name:     "valid 64-character commit sha",
			versions: []string{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
			wantErr:  false,
		},
		{
			name:     "valid combination of exact tag and commit sha",
			versions: []string{"v1.0.0", "11bd71901bbe5b1630ceea73d27597364c9af683"},
			wantErr:  false,
		},

		// Rejected moving major tags
		{
			name:     "invalid moving tag v4",
			versions: []string{"v4"},
			wantErr:  true,
		},
		{
			name:     "invalid moving tag 4",
			versions: []string{"4"},
			wantErr:  true,
		},
		{
			name:     "invalid moving tag v1",
			versions: []string{"v1"},
			wantErr:  true,
		},
		{
			name:     "invalid moving tag 1",
			versions: []string{"1"},
			wantErr:  true,
		},
		{
			name:     "invalid moving tag uppercase V4",
			versions: []string{"V4"},
			wantErr:  true,
		},

		// Rejected moving branch names
		{
			name:     "invalid branch name latest",
			versions: []string{"latest"},
			wantErr:  true,
		},
		{
			name:     "invalid branch name main",
			versions: []string{"main"},
			wantErr:  true,
		},
		{
			name:     "invalid branch name master",
			versions: []string{"master"},
			wantErr:  true,
		},
		{
			name:     "invalid branch name head",
			versions: []string{"head"},
			wantErr:  true,
		},
		{
			name:     "invalid branch name uppercase HEAD",
			versions: []string{"HEAD"},
			wantErr:  true,
		},
		{
			name:     "invalid branch name dev",
			versions: []string{"dev"},
			wantErr:  true,
		},
		{
			name:     "invalid branch name nightly",
			versions: []string{"nightly"},
			wantErr:  true,
		},
		{
			name:     "invalid branch name canary",
			versions: []string{"canary"},
			wantErr:  true,
		},
		{
			name:     "invalid branch name trunk",
			versions: []string{"trunk"},
			wantErr:  true,
		},
		{
			name:     "invalid branch name stable",
			versions: []string{"stable"},
			wantErr:  true,
		},

		// Rejected zero version
		{
			name:     "invalid zero version 0",
			versions: []string{"0"},
			wantErr:  true,
		},
		{
			name:     "invalid zero version v0",
			versions: []string{"v0"},
			wantErr:  true,
		},

		// Rejected malformed / whitespace versions
		{
			name:     "invalid empty version string",
			versions: []string{""},
			wantErr:  true,
		},
		{
			name:     "invalid version leading whitespace",
			versions: []string{" v1.0.0"},
			wantErr:  true,
		},
		{
			name:     "invalid version trailing whitespace",
			versions: []string{"v1.0.0 "},
			wantErr:  true,
		},
		{
			name:     "invalid version inner whitespace",
			versions: []string{"v1.0. 0"},
			wantErr:  true,
		},
		{
			name:     "invalid mixed valid and moving tag",
			versions: []string{"v1.0.0", "v4"},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			vuln := &osvschema.Vulnerability{
				Affected: []*osvschema.Affected{
					{
						Package: &osvschema.Package{
							Ecosystem: string(osvconstants.EcosystemGitHubActions),
							Name:      "actions/checkout",
						},
						Versions: tt.versions,
					},
				},
			}
			err := report.ValidateVuln(vuln)
			if tt.wantErr {
				if !errors.Is(err, report.ErrInvalidOSV) {
					t.Errorf("ValidateVuln() error = %v; want error wrapping ErrInvalidOSV", err)
				}
			} else if err != nil {
				t.Errorf("ValidateVuln() unexpected error = %v", err)
			}
		})
	}
}

func TestValidateVuln_GitHubActions_Ranges(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ranges  []*osvschema.Range
		wantErr bool
	}{
		// Valid ECOSYSTEM ranges
		{
			name: "valid ecosystem range with 0 introduced and exact tag fixed",
			ranges: []*osvschema.Range{
				{
					Type: osvschema.Range_ECOSYSTEM,
					Events: []*osvschema.Event{
						{Introduced: "0"},
						{Fixed: "1.0.1"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid ecosystem range with 0 introduced and v-prefixed tag fixed",
			ranges: []*osvschema.Range{
				{
					Type: osvschema.Range_ECOSYSTEM,
					Events: []*osvschema.Event{
						{Introduced: "0"},
						{Fixed: "v4.0.1"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid ecosystem range with exact tags introduced and fixed",
			ranges: []*osvschema.Range{
				{
					Type: osvschema.Range_ECOSYSTEM,
					Events: []*osvschema.Event{
						{Introduced: "1.0.0"},
						{Fixed: "1.0.1"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid ecosystem range with commit sha fixed",
			ranges: []*osvschema.Range{
				{
					Type: osvschema.Range_ECOSYSTEM,
					Events: []*osvschema.Event{
						{Introduced: "0"},
						{Fixed: "11bd71901bbe5b1630ceea73d27597364c9af683"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid ecosystem range with commit sha introduced and fixed",
			ranges: []*osvschema.Range{
				{
					Type: osvschema.Range_ECOSYSTEM,
					Events: []*osvschema.Event{
						{Introduced: "b4ffde65f46336ab88eb53be808477a3936bae11"},
						{Fixed: "11bd71901bbe5b1630ceea73d27597364c9af683"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid ecosystem range with last_affected exact tag",
			ranges: []*osvschema.Range{
				{
					Type: osvschema.Range_ECOSYSTEM,
					Events: []*osvschema.Event{
						{Introduced: "0"},
						{LastAffected: "4.0.0"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid ecosystem range with two-digit tag v4.1 fixed",
			ranges: []*osvschema.Range{
				{
					Type: osvschema.Range_ECOSYSTEM,
					Events: []*osvschema.Event{
						{Introduced: "0"},
						{Fixed: "v4.1"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid ecosystem range with two-digit tag v4.1 introduced",
			ranges: []*osvschema.Range{
				{
					Type: osvschema.Range_ECOSYSTEM,
					Events: []*osvschema.Event{
						{Introduced: "v4.1"},
						{Fixed: "4.1.1"},
					},
				},
			},
			wantErr: false,
		},

		// Rejected moving tags in ECOSYSTEM ranges
		{
			name: "invalid ecosystem range with moving tag v4 fixed",
			ranges: []*osvschema.Range{
				{
					Type: osvschema.Range_ECOSYSTEM,
					Events: []*osvschema.Event{
						{Introduced: "0"},
						{Fixed: "v4"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid ecosystem range with moving tag main fixed",
			ranges: []*osvschema.Range{
				{
					Type: osvschema.Range_ECOSYSTEM,
					Events: []*osvschema.Event{
						{Introduced: "0"},
						{Fixed: "main"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid ecosystem range with moving tag latest fixed",
			ranges: []*osvschema.Range{
				{
					Type: osvschema.Range_ECOSYSTEM,
					Events: []*osvschema.Event{
						{Introduced: "0"},
						{Fixed: "latest"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid ecosystem range with moving tag v4 introduced",
			ranges: []*osvschema.Range{
				{
					Type: osvschema.Range_ECOSYSTEM,
					Events: []*osvschema.Event{
						{Introduced: "v4"},
						{Fixed: "4.0.1"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid ecosystem range with moving tag main introduced",
			ranges: []*osvschema.Range{
				{
					Type: osvschema.Range_ECOSYSTEM,
					Events: []*osvschema.Event{
						{Introduced: "main"},
						{Fixed: "4.0.1"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid ecosystem range with 0 fixed",
			ranges: []*osvschema.Range{
				{
					Type: osvschema.Range_ECOSYSTEM,
					Events: []*osvschema.Event{
						{Introduced: "1.0.0"},
						{Fixed: "0"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid ecosystem range with whitespace in event",
			ranges: []*osvschema.Range{
				{
					Type: osvschema.Range_ECOSYSTEM,
					Events: []*osvschema.Event{
						{Introduced: "0"},
						{Fixed: " 1.0.1"},
					},
				},
			},
			wantErr: true,
		},

		// Valid GIT ranges
		{
			name: "valid git range with commit sha introduced and fixed",
			ranges: []*osvschema.Range{
				{
					Type: osvschema.Range_GIT,
					Repo: "https://github.com/actions/checkout",
					Events: []*osvschema.Event{
						{Introduced: "0"},
						{Fixed: "11bd71901bbe5b1630ceea73d27597364c9af683"},
					},
				},
			},
			wantErr: false,
		},

		// Rejected GIT ranges with non-commit IDs
		{
			name: "invalid git range with moving tag v4 fixed",
			ranges: []*osvschema.Range{
				{
					Type: osvschema.Range_GIT,
					Repo: "https://github.com/actions/checkout",
					Events: []*osvschema.Event{
						{Introduced: "0"},
						{Fixed: "v4"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid git range with branch name main fixed",
			ranges: []*osvschema.Range{
				{
					Type: osvschema.Range_GIT,
					Repo: "https://github.com/actions/checkout",
					Events: []*osvschema.Event{
						{Introduced: "0"},
						{Fixed: "main"},
					},
				},
			},
			wantErr: true,
		},

		// Rejected SEMVER ranges
		{
			name: "invalid range type SEMVER not supported for GitHub Actions",
			ranges: []*osvschema.Range{
				{
					Type: osvschema.Range_SEMVER,
					Events: []*osvschema.Event{
						{Introduced: "0"},
						{Fixed: "1.0.1"},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			vuln := &osvschema.Vulnerability{
				Affected: []*osvschema.Affected{
					{
						Package: &osvschema.Package{
							Ecosystem: string(osvconstants.EcosystemGitHubActions),
							Name:      "actions/checkout",
						},
						Ranges: tt.ranges,
					},
				},
			}
			err := report.ValidateVuln(vuln)
			if tt.wantErr {
				if !errors.Is(err, report.ErrInvalidOSV) {
					t.Errorf("ValidateVuln() error = %v; want error wrapping ErrInvalidOSV", err)
				}
			} else if err != nil {
				t.Errorf("ValidateVuln() unexpected error = %v", err)
			}
		})
	}
}
