package gitname

import (
	"net/url"
	"strings"
)

type gitHostHandler struct {
	CheckPath    func(string) bool
	CanonScheme  string
	CanonPath    func(string) string
	KeepUser     bool
	EnsureGitExt bool
}

// Canon canonicalizes the supplied url for a specific git hosting service
// based on the configuration in the gitHostHandler.
func (h *gitHostHandler) Canon(u *url.URL) {
	// Replace the scheme if we have an override.
	if h.CanonScheme != "" {
		u.Scheme = h.CanonScheme
	}

	// Fix the path.
	u.Path = h.CanonPath(u.Path)

	// Strip the user if we should not keep it.
	if !h.KeepUser {
		u.User = nil
	}

	// Ensure the .git extension is always present.
	if !strings.HasSuffix(u.Path, ".git") {
		u.Path = u.Path + ".git"
	}
}

// defaultGitHost covers common git hosting services that have a url structure
// of "example.com/org/repo.git", where "org" and "repo" are case-insensitive.
var defaultGitHost = &gitHostHandler{
	CheckPath:    checkOrgRepoPath,
	CanonScheme:  "https",
	CanonPath:    strings.ToLower,
	KeepUser:     false,
	EnsureGitExt: true,
}

// sensitiveRepoGitHost is similar to defaultGitHost, except it preserves the
// case on the "repo" part of the URL.
var sensitiveRepoGitHost = &gitHostHandler{
	CheckPath:    checkOrgRepoPath,
	CanonScheme:  "https",
	CanonPath:    canonLowerOrgPath,
	KeepUser:     false,
	EnsureGitExt: true,
}

var gitHosts = map[string]*gitHostHandler{
	".googlesource.com": defaultGitHost,
	"github.com":        defaultGitHost,
	"gitlab.com":        defaultGitHost,
	"bitbucket.org":     defaultGitHost,
	"codeberg.org":      defaultGitHost,
	"gitee.com":         sensitiveRepoGitHost,
	"gitee.cn":          sensitiveRepoGitHost,
}

func handlerForHost(host string) *gitHostHandler {
	if handler, ok := gitHosts[host]; ok {
		// There is a direct match, so return the handler immediately.
		return handler
	}
	for suffix, handler := range gitHosts {
		if suffix[0] != '.' {
			// The suffix must start with a "." to ensure subdomains are
			// matched correctly.
			continue
		}
		if strings.HasSuffix(host, suffix) {
			// The suffix matches the given host, so return the handler.
			return handler
		}
	}
	return nil
}

// checkOrgRepoPath ensures that the path being supplied only has two path
// components.
func checkOrgRepoPath(path string) bool {
	tail := strings.TrimLeft(path, "/")
	parts := strings.SplitN(tail, "/", 2)
	if len(parts) != 2 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 {
			return false
		}
	}
	return true
}

// canonLowerOrg lowercases the first path component in the supplied path.
func canonLowerOrgPath(path string) string {
	parts := strings.Split(path, "/")
	for i := 0; i < len(parts); i++ {
		p := parts[i]
		if len(p) == 0 {
			// Skip empty parts.
			continue
		}
		parts[i] = strings.ToLower(p)
		break
	}
	return strings.Join(parts, "/")
}
