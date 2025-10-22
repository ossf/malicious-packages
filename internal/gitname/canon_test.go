package gitname_test

import (
	"testing"

	"github.com/ossf/malicious-packages/internal/gitname"
)

func TestCanonForStorage(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{
			name: "https://github.com/org/repo.git",
			want: "github.com/org/repo",
		},
		{
			name: "git@github.com:org/repo.git",
			want: "github.com/org/repo",
		},
		{
			name: "ssh://git@GITHUB.COM/Org/Repo.git",
			want: "github.com/org/repo",
		},
		{
			name: "https://go.googlesource.com/go",
			want: "go.googlesource.com/go",
		},
		{
			name: "random@example.com:path/to/repo.git",
			want: "random@example.com/path/to/repo",
		},
		{
			name: "git@gitee.com:ignOre/CASE.git",
			want: "gitee.com/ignore/CASE",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := gitname.CanonForStorage(test.name)
			if got != test.want {
				t.Fatalf("canonGitRepo() = %q; want %q", got, test.want)
			}
		})
	}
}
