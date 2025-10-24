package gitname

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// ErrInvalidGitRepo is wrapped by any errors returned by Parse.
var ErrInvalidGitRepo = errors.New("invalid git repository")

var validGitRemoteSchemes = []string{
	"http",
	"https",
	"ssh",
	"git",
}

// Parse parses a git repository name into a url.URL. If the name cannot be
// parsed an error will be returned, and the url will be nil.
//
// Both URL and SCP-like git repository names are supported.
func Parse(name string) (*url.URL, error) {
	u, err := url.Parse(name)
	if err != nil {
		u, err = parseSSH(name)
		if err != nil {
			return nil, err
		}
	}
	if !slices.Contains(validGitRemoteSchemes, u.Scheme) {
		return nil, fmt.Errorf("%w: unsupported git scheme", ErrInvalidGitRepo)
	}
	return u, nil
}

func parseSSH(name string) (*url.URL, error) {
	// Hunt for the end of an IPv6 address first, to avoid matching the colons
	// in the IPv6 path itself.
	ipv6_end := strings.Index(name, "]:")
	path_idx := 0

	if ipv6_end >= 0 {
		// Skip the separator "]:"
		path_idx = ipv6_end + 2
	} else {
		i := strings.Index(name, ":")
		if i < 0 {
			// No path seperator.
			return nil, fmt.Errorf("%w: no path separator", ErrInvalidGitRepo)
		}
		// Skip the separator ":"
		path_idx = i + 1
	}

	path := name[path_idx:]
	if len(path) == 0 {
		// No path.
		return nil, fmt.Errorf("%w: empty path", ErrInvalidGitRepo)
	} else if path[0] == '/' {
		// Absolute path is unsupported.
		return nil, fmt.Errorf("%w: absolute path", ErrInvalidGitRepo)
	}
	// TODO: should we force a ".git" suffix?

	user_host := name[0 : path_idx-1]
	if len(user_host) == 0 {
		// No host or user
		return nil, fmt.Errorf("%w: no user or host", ErrInvalidGitRepo)
	}

	// Build a raw URL string that we parse later from the components of the
	// Git scp-like repository.
	raw := "ssh://"

	user_end := strings.LastIndex(user_host, "@")
	switch {
	case user_end == 0:
		// Empty user
		return nil, fmt.Errorf("%w: empty user", ErrInvalidGitRepo)
	case user_end == len(user_host)-1:
		// Empty host
		return nil, fmt.Errorf("%w: empty host", ErrInvalidGitRepo)
	default:
		raw = raw + user_host
	}

	raw = raw + "/" + path
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidGitRepo, err)
	}

	return u, nil
}
