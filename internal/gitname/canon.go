package gitname

import (
	"net/url"
	"strings"
)

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
