package gitname

import (
	"net/url"
	"strings"
)

// Canon will canonicalize the a git repository name as returned by Parse.
//
// The method adjusts it's behaviour based on the hostname to ensure that
// URLs are correctly canonicalized for each git hosting provider.
//
// Any password present in the URL will be stripped.
func Canon(name *url.URL) *url.URL {
	u := *name // shallow copy

	u.Host = strings.ToLower(u.Host)

	// We can only adjust the hosts we are aware of.
	if handler := handlerForHost(u.Host); handler != nil {
		handler.Canon(&u)
	}

	// Always strip passwords if they are present.
	if _, ok := u.User.Password(); ok {
		u.User = url.User(u.User.Username())
	}

	return &u
}

// CanonForStorage canonicalizes the git repository name and ensures that it
// is nicely formatted for use in output.
//
// The scheme is dropped from the URL.
// If the username is "git" it is dropped.
// The ".git" suffix is removed.
//
// If the repository name is invalid, the string is returned without changes.
func CanonForStorage(name string) string {
	u, err := Parse(name)
	if err != nil {
		return name
	}

	u = Canon(u)

	u.Scheme = ""

	if u.User.Username() == "git" {
		u.User = nil
	}

	u.Path, _ = strings.CutSuffix(u.Path, ".git")

	canon := u.String()
	canon = canon[2:] // Strip "//" prefix
	return canon
}
