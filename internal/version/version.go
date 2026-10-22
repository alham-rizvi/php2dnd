// Package version maps PHP version strings to vulnerability status for
// CVE-2026-109618 / CVE-2026-109619 (session.upload_progress injection chain).
package version

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Status represents the vulnerability classification of a PHP version.
type Status int

const (
	StatusUnknown    Status = iota
	StatusVulnerable        // confirmed affected build
	StatusPatched           // at or above the fixed release
	StatusEOL               // end-of-life branch, no official patch
)

func (s Status) String() string {
	switch s {
	case StatusVulnerable:
		return "VULNERABLE"
	case StatusPatched:
		return "PATCHED"
	case StatusEOL:
		return "EOL-VULNERABLE"
	default:
		return "UNKNOWN"
	}
}

// branchFix maps (major, minor) -> first patched patch level.
// Source: CVE advisory fixed-release table.
var branchFix = map[[2]int]int{
	{8, 2}: 35,
	{8, 3}: 36,
	{8, 4}: 27,
	{8, 5}: 12,
}

// eolBranches are end-of-life; treated as vulnerable when upload_progress exists.
var eolBranches = map[[2]int]bool{
	{8, 1}: true, {8, 0}: true,
	{7, 4}: true, {7, 3}: true, {7, 2}: true, {7, 1}: true, {7, 0}: true,
	{5, 6}: true, {5, 5}: true, {5, 4}: true,
}

// phpVersionRe extracts a dotted version from any string (header or body).
var phpVersionRe = regexp.MustCompile(`PHP[/ ]([\d]+\.[\d]+\.[\d]+)`)

// Result holds classification details.
type Result struct {
	Raw    string // raw version string, empty if not found
	Status Status
	Note   string
}

// Classify returns a Result for the given dotted PHP version string.
func Classify(ver string) Result {
	parts := strings.SplitN(ver, ".", 3)
	if len(parts) != 3 {
		return Result{Raw: ver, Status: StatusUnknown, Note: "could not parse version"}
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	patch, err3 := strconv.Atoi(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return Result{Raw: ver, Status: StatusUnknown, Note: "non-numeric version components"}
	}

	branch := [2]int{major, minor}

	if fix, ok := branchFix[branch]; ok {
		if patch < fix {
			return Result{
				Raw:    ver,
				Status: StatusVulnerable,
				Note:   fmt.Sprintf("%s < %d.%d.%d (patched release)", ver, major, minor, fix),
			}
		}
		return Result{
			Raw:    ver,
			Status: StatusPatched,
			Note:   fmt.Sprintf("%s >= %d.%d.%d", ver, major, minor, fix),
		}
	}

	if eolBranches[branch] {
		return Result{
			Raw:    ver,
			Status: StatusEOL,
			Note:   fmt.Sprintf("%d.%d.x is end-of-life; no official fix", major, minor),
		}
	}

	if major > 8 || (major == 8 && minor > 5) {
		return Result{Raw: ver, Status: StatusUnknown, Note: "newer than advisory range"}
	}

	return Result{Raw: ver, Status: StatusUnknown, Note: "not in advisory table"}
}

// ExtractFromBanner searches response headers/body text for a PHP version string.
func ExtractFromBanner(sources ...string) string {
	for _, s := range sources {
		if m := phpVersionRe.FindStringSubmatch(s); m != nil {
			return m[1]
		}
	}
	return ""
}
