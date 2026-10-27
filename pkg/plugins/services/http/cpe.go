package http

import (
	"slices"
	"strings"
	"sync"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// getWappalyzer compiles the fingerprint DB (~200ms) on first use only, so runs
// that never get an HTTP response don't pay for it. Safe for concurrent use.
var getWappalyzer = sync.OnceValues(wappalyzer.New)

// ExtractCPEs passively matches an already-fetched response against the
// wappalyzer fingerprints and returns the CPEs of the detected technologies.
// If wappalyzer extracted a version, it is filled into the CPE's version field.
func ExtractCPEs(headers map[string][]string, body []byte) []string {
	wa, err := getWappalyzer()
	if err != nil {
		return nil
	}
	apps := wa.GetFingerprints().Apps

	var cpes []string
	for tech := range wa.Fingerprint(headers, body) {
		// tech is "Name" or "Name:version"; names may contain ':' themselves (e.g. "Re:amaze")
		name, version := tech, ""
		if _, ok := apps[name]; !ok {
			if i := strings.LastIndex(tech, ":"); i > 0 {
				name, version = tech[:i], tech[i+1:]
			}
		}
		app, ok := apps[name]
		if !ok {
			continue
		}
		cpe := strings.TrimSpace(app.CPE)
		if cpe == "" {
			continue
		}
		cpes = append(cpes, withVersion(cpe, version))
	}

	slices.Sort(cpes)
	return slices.Compact(cpes)
}

// withVersion sets the version field of a CPE 2.3 string, if it is a wildcard.
func withVersion(cpe, version string) string {
	if version == "" {
		return cpe
	}
	parts := strings.Split(cpe, ":")
	if len(parts) != 13 || parts[5] != "*" {
		return cpe
	}
	parts[5] = escapeCPEValue(strings.ToLower(version))
	return strings.Join(parts, ":")
}

// escapeCPEValue backslash-quotes characters not allowed unquoted in a CPE 2.3
// formatted string (everything except alphanumerics, '.', '-' and '_').
func escapeCPEValue(s string) string {
	var b strings.Builder
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_') {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}
