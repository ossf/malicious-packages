package gitname_test

import (
	"net/url"
	"testing"

	"github.com/ossf/malicious-packages/internal/gitname"
)

func TestCanon(t *testing.T) {
	//nolint:gosec // disable check due to leaked credentials false-positive
	tests := map[string]string{
		"https://github.com/org/repo.git":          "https://github.com/org/repo.git",
		"https://github.com/org/repo":              "https://github.com/org/repo.git",
		"http://github.com/org/repo.git":           "https://github.com/org/repo.git",
		"ssh://git@GITHUB.COM/Org/Repo.git":        "https://github.com/org/repo.git",
		"ssh://anyuser@gitlab.com/org/REPO.git":    "https://gitlab.com/org/repo.git",
		"https://go.googlesource.com/go":           "https://go.googlesource.com/go",
		"https://gitee.com/ignOre/CASE.git":        "https://gitee.com/ignore/CASE.git",
		"git://user:password@example.com/repo.git": "git://user@example.com/repo.git",
	}
	for repo, want := range tests {
		t.Run(repo, func(t *testing.T) {
			u, err := url.Parse(repo)
			if err != nil {
				t.Fatalf("url.Parse() = %v; want no error", err)
			}
			got := gitname.Canon(u).String()
			if got != want {
				t.Fatalf("Canon() = %q; want %q", got, want)
			}
		})
	}
}

func TestCanonForStorage(t *testing.T) {
	tests := map[string]string{
		"invalid:":                            "invalid:",
		"invalid":                             "invalid",
		"ftp://invalid.com/repo.git":          "ftp://invalid.com/repo.git",
		"https://github.com/org/repo.git":     "github.com/org/repo",
		"git@github.com:org/repo.git":         "github.com/org/repo",
		"ssh://git@GITHUB.COM/Org/Repo.git":   "github.com/org/repo",
		"https://go.googlesource.com/go":      "go.googlesource.com/go",
		"random@example.com:path/to/repo.git": "random@example.com/path/to/repo",
		"git@gitee.com:ignOre/CASE.git":       "gitee.com/ignore/CASE",
		"git@example.com:repo.git":            "example.com/repo",
	}
	for repo, want := range tests {
		t.Run(repo, func(t *testing.T) {
			got := gitname.CanonForStorage(repo)
			if got != want {
				t.Fatalf("CanonForStorage() = %q; want %q", got, want)
			}
		})
	}
}
