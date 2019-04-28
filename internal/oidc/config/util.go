package config

import (
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strings"
)

/*
func urisToStrings(urls []url.URL) []string {
	if len(urls) == 0 {
		return nil
	}
	sli := make([]string, len(urls))
	for i, u := range urls {
		sli[i] = u.String()
	}
	return sli
}
*/

func uriToString(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.String()
}

// stickyErrParser parses URIs and email addresses. Once it encounters
// a parse error, subsequent calls become no-op.
type stickyErrParser struct {
	firstErr error
}

func (p *stickyErrParser) parseURI(s, field string) *url.URL {
	if p.firstErr != nil || s == "" {
		return nil
	}
	u, err := url.Parse(s)
	if err == nil {
		if u.Host == "" {
			err = errors.New("no host in URI")
		} else if u.Scheme != "http" && u.Scheme != "https" {
			err = errors.New("invalid URI scheme")
		}
	}
	if err != nil {
		p.firstErr = fmt.Errorf("failed to parse %s: %v", field, err)
		return nil
	}
	return u
}

func (p *stickyErrParser) parseURIs(s []string, field string) []url.URL {
	if p.firstErr != nil || len(s) == 0 {
		return nil
	}
	uris := make([]url.URL, len(s))
	for i, val := range s {
		if val == "" {
			p.firstErr = fmt.Errorf("invalid URI in field %s", field)
			return nil
		}
		if u := p.parseURI(val, field); u != nil {
			uris[i] = *u
		}
	}
	return uris
}

func (p *stickyErrParser) parseEmails(s []string, field string) []mail.Address {
	if p.firstErr != nil || len(s) == 0 {
		return nil
	}
	addrs := make([]mail.Address, len(s))
	for i, addr := range s {
		if addr == "" {
			p.firstErr = fmt.Errorf("invalid email in field %s", field)
			return nil
		}
		a, err := mail.ParseAddress(addr)
		if err != nil {
			p.firstErr = fmt.Errorf("invalid email in field %s: %v", field, err)
			return nil
		}
		addrs[i] = *a
	}
	return addrs
}

// urlEqual checks two urls for equality using only the host and path portions.
func urlEqual(url1, url2 string) bool {
	u1, err := url.Parse(url1)
	if err != nil {
		return false
	}
	u2, err := url.Parse(url2)
	if err != nil {
		return false
	}

	return strings.ToLower(u1.Host+u1.Path) == strings.ToLower(u2.Host+u2.Path)
}
