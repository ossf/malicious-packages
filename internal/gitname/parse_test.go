package gitname_test

import (
	"testing"

	"github.com/ossf/malicious-packages/internal/gitname"
)

func TestParse_InvalidRepo(t *testing.T) {
	tests := map[string]string{
		"empty":                  "",
		"junk":                   "this is junk",
		"invalid scheme":         "ftp://example.com/repo.git",
		"missing host":           "https:///repo.git",
		"missing path 1":         "https://github.com",
		"missing path 2":         "https://github.com/",
		"ssh missing host":       "git@:repo.git",
		"ssh empty path":         "git@example.com:",
		"ssh no path":            "git@example.com",
		"ssh absolute path":      "git@example.com:/repo.git",
		"ssh only path":          ":repo.git",
		"ssh empty host":         "git@:repo.git",
		"ssh empty user":         "@example.com:repo.git",
		"ssh IPv6":               "git@[:repo.git",
		"github long path":       "https://github.com/this/is/invalid.git",
		"github short path":      "https://github.com/invalid.git",
		"github empty seg":       "https://github.com/a/",
		"googlesource long path": "https://go.googlesource.com/invalid/repo.git",
	}
	for name, repo := range tests {
		t.Run(name, func(t *testing.T) {
			u, err := gitname.Parse(repo)
			if err == nil {
				t.Errorf("Parse() = nil; want an error")
			}
			if u != nil {
				t.Errorf("Parse() = %v; want nil", u)
			}
		})
	}
}

func TestParse_Valid(t *testing.T) {
	tests := []struct {
		name string
		repo string
		want string
	}{
		{
			name: "https url",
			repo: "https://github.com/org/repo.git",
		},
		{
			name: "https caps",
			repo: "https://GITHUB.COM/ORG/REPO.git",
		},
		{
			name: "git url",
			repo: "git://example.com/repo.git",
		},
		{
			name: "url with port",
			repo: "https://github.com:443/org/repo.git",
		},
		{
			name: "scp style",
			repo: "git@github.com:org/repo.git",
			want: "ssh://git@github.com/org/repo.git",
		},
		{
			name: "scp no user",
			repo: "example.com:org/repo.git",
			want: "ssh://example.com/org/repo.git",
		},
		{
			name: "scp ipv6",
			repo: "git@[::1]:repo.git",
			want: "ssh://git@[::1]/repo.git",
		},
		{
			name: "scp ipv4",
			repo: "git@127.0.0.1:repo.git",
			want: "ssh://git@127.0.0.1/repo.git",
		},
		{
			name: "scp domain in user",
			repo: "git@example.com@example.org:path/to/repo.git",
			want: "ssh://git%40example.com@example.org/path/to/repo.git",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// By default we expect to see what was passed in, unless an
			// explicit "want" was specified in the test case.
			want := test.repo
			if test.want != "" {
				want = test.want
			}
			u, err := gitname.Parse(test.repo)
			if err != nil {
				t.Errorf("Parse() = %v; want no error", err)
			}
			got := u.String()
			if got != want {
				t.Errorf("Parse() = %q; want %q", got, want)
			}
		})
	}
}
