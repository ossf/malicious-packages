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
	ipv6End := strings.Index(name, "]:")
	pathIdx := 0

	if ipv6End >= 0 {
		// Skip the separator "]:"
		pathIdx = ipv6End + 2
	} else {
		i := strings.Index(name, ":")
		if i < 0 {
			return nil, fmt.Errorf("%w: no path separator", ErrInvalidGitRepo)
		}
		// Skip the separator ":"
		pathIdx = i + 1
	}

	path := name[pathIdx:]
	if len(path) == 0 {
		return nil, fmt.Errorf("%w: empty path", ErrInvalidGitRepo)
	} else if path[0] == '/' {
		return nil, fmt.Errorf("%w: absolute path", ErrInvalidGitRepo)
	}
	// TODO: should we force a ".git" suffix?

	userHost := name[0 : pathIdx-1]
	if len(userHost) == 0 {
		return nil, fmt.Errorf("%w: no user or host", ErrInvalidGitRepo)
	}

	// Build a raw URL string that we parse later from the components of the
	// Git scp-like repository.
	raw := "ssh://"

	userEnd := strings.LastIndex(userHost, "@")
	switch {
	case userEnd == 0:
		return nil, fmt.Errorf("%w: empty user", ErrInvalidGitRepo)
	case userEnd == len(userHost)-1:
		return nil, fmt.Errorf("%w: empty host", ErrInvalidGitRepo)
	default:
		raw += userHost
	}

	raw += "/" + path
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidGitRepo, err)
	}

	return u, nil
}
