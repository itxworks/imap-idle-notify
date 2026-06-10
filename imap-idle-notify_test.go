package main

import (
	"testing"

	"github.com/emersion/go-imap"
)

// headerSafe must replace control characters (regression for commit 0bda435:
// a crafted sender/subject must not be able to break the notification request).
func TestHeaderSafe(t *testing.T) {
	cases := map[string]string{
		"plain@example.com":   "plain@example.com",
		"a\x01b":              "a b",
		"line\nbreak":         "line break",
		"tab\there":           "tab here",
		"del\x7fchar":         "del char",
		"unicodé ✓ kept":      "unicodé ✓ kept",
	}
	for in, want := range cases {
		if got := headerSafe(in); got != want {
			t.Errorf("headerSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

// check matches exact addresses case-insensitively and treats an @-prefixed
// pattern as a domain suffix match.
func TestCheck(t *testing.T) {
	AllowedFrom = map[string]bool{
		"alice@example.com": true,
		"@trusted.org":      true,
	}
	addr := func(mbox, host string) []*imap.Address {
		return []*imap.Address{{MailboxName: mbox, HostName: host}}
	}
	cases := []struct {
		name  string
		addrs []*imap.Address
		want  bool
	}{
		{"exact match", addr("alice", "example.com"), true},
		{"exact match is case-insensitive", addr("ALICE", "EXAMPLE.COM"), true},
		{"non-matching exact address", addr("bob", "example.com"), false},
		{"domain pattern matches any sender", addr("anyone", "trusted.org"), true},
		{"address outside domain", addr("anyone", "other.org"), false},
		{"no addresses", nil, false},
	}
	for _, c := range cases {
		if got := check(c.addrs); got != c.want {
			t.Errorf("%s: check(...) = %v, want %v", c.name, got, c.want)
		}
	}
}
