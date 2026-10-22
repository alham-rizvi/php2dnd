// Package report formats ScanResults for terminal, JSON, and Markdown output.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/php2shell-scanner/internal/checker"
	"github.com/php2shell-scanner/internal/version"
)

// ---- ANSI color helpers -----------------------------------------------------

const reset = "\033[0m"

type color int

const (
	colorRed    color = 31
	colorGreen  color = 32
	colorYellow color = 33
	colorCyan   color = 36
	colorGrey   color = 90
	colorBold   color = 1
)

func col(text string, colors ...color) string {
	codes := make([]string, len(colors))
	for i, c := range colors {
		codes[i] = fmt.Sprintf("%d", c)
	}
	return fmt.Sprintf("\033[%sm%s%s", strings.Join(codes, ";"), text, reset)
}

// ---- Banner -----------------------------------------------------------------

func PrintBanner(w io.Writer, noColor bool) {
	banner := `
  ____  _   _ ____  ____      _          _ _
 |  _ \| | | |  _ \|___ \  __| |_ __  __| | |
 | |_) | |_| | |_) | __) |/ _' | '_ \/ _' | |
 |  __/|  _  |  __/ / __/| (_| | | | | (_| |_|
 |_|   |_| |_|_|   |_____|\__,_|_| |_|\__,_(_)

  php2shell-scanner  --  CVE-2026-109618 / CVE-2026-109619
  Non-destructive validator for session.upload_progress injection
`
	if noColor {
		fmt.Fprintln(w, banner)
		return
	}
	fmt.Fprintln(w, col(banner, colorCyan, colorBold))
}

// ---- Terminal output --------------------------------------------------------

// PrintResult writes a full colored terminal report to w.
func PrintResult(w io.Writer, r checker.ScanResult, noColor bool) {
	c := func(text string, colors ...color) string {
		if noColor {
			return text
		}
		return col(text, colors...)
	}

	fmt.Fprintf(w, "\n%s\n", c("=== SCAN RESULT ===", colorCyan, colorBold))
	fmt.Fprintf(w, "  Target    : %s\n", r.Target)
	fmt.Fprintf(w, "  Scanned   : %s\n", r.ScannedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "  Duration  : %s\n\n", r.Duration.Round(time.Millisecond))

	if r.Error != "" {
		fmt.Fprintf(w, "  %s\n", c("[ERR] "+r.Error, colorRed))
		return
	}

	// PHP version line
	verLabel := versionLabel(r.PHPVersion.Status, noColor)
	fmt.Fprintf(w, "  PHP       : %s %s\n",
		c(ifEmpty(r.PHPVersion.Raw, "?"), colorBold),
		verLabel)
	fmt.Fprintf(w, "             %s\n\n", c(r.PHPVersion.Note, colorGrey))

	// Probe table
	fmt.Fprintf(w, "  %s\n", c("Probes:", colorBold))
	for i, p := range r.Probes {
		idx := fmt.Sprintf("[%d]", i+1)
		tick := c("PASS", colorGreen)
		if !p.Passed {
			tick = c("SKIP", colorGrey)
			if p.Name != "canary_lfi" || p.Detail != "" && !strings.HasPrefix(p.Detail, "skipped") {
				if strings.Contains(p.Detail, "error") || strings.Contains(p.Detail, "NOT") {
					tick = c("FAIL", colorRed)
				}
			}
		}
		fmt.Fprintf(w, "  %s %-12s %s  %s\n", idx, p.Name, tick, p.Detail)
		if p.RawData != "" {
			fmt.Fprintf(w, "             %s\n", c(p.RawData, colorGrey))
		}
	}

	// Canary info
	if r.CanaryToken != "" {
		fmt.Fprintf(w, "\n  %s  %s\n", c("Canary token :", colorGrey), r.CanaryToken)
		if r.CanaryPath != "" {
			fmt.Fprintf(w, "  %s  %s\n", c("Session file  :", colorGrey), r.CanaryPath)
			fmt.Fprintf(w, "  %s\n", c("(swap token for <?php ?> => RCE; see poc/ for reference)", colorGrey))
		}
	}

	// Final verdict
	fmt.Fprintf(w, "\n  %s\n", c("---", colorGrey))
	fmt.Fprintf(w, "  Verdict   : %s\n", verdictLabel(r.Verdict, noColor))
	fmt.Fprintf(w, "  Detail    : %s\n", c(r.VerdictNote, colorGrey))

	// Mitigation
	fmt.Fprintf(w, "\n  %s\n", c("Mitigation:", colorYellow))
	fmt.Fprintf(w, "    %s\n", c("session.upload_progress.enabled = Off", colorYellow))
	fmt.Fprintf(w, "    %s\n", c("session.use_only_cookies = On", colorYellow))
	fmt.Fprintf(w, "    %s\n\n", c("Patch PHP to the fixed release for your branch.", colorYellow))
}

// PrintMultiSummary prints a compact table across multiple results (batch mode).
func PrintMultiSummary(w io.Writer, results []checker.ScanResult, noColor bool) {
	c := func(text string, colors ...color) string {
		if noColor {
			return text
		}
		return col(text, colors...)
	}

	fmt.Fprintf(w, "\n%s\n", c("=== BATCH SUMMARY ===", colorCyan, colorBold))
	fmt.Fprintf(w, "  %-40s  %-10s  %-25s  %s\n",
		"Target", "PHP", "Verdict", "Duration")
	fmt.Fprintf(w, "  %s\n", strings.Repeat("-", 95))

	for _, r := range results {
		ver := ifEmpty(r.PHPVersion.Raw, "?")
		dur := r.Duration.Round(time.Millisecond).String()
		verd := r.Verdict.String()
		errStr := ""
		if r.Error != "" {
			verd = "ERROR"
			errStr = " (" + r.Error + ")"
		}
		line := fmt.Sprintf("  %-40s  %-10s  %-25s  %s%s",
			r.Target, ver, verd, dur, errStr)
		switch r.Verdict {
		case checker.VerdictConfirmed, checker.VerdictLikelyVulnerable:
			fmt.Fprintln(w, c(line, colorRed))
		case checker.VerdictPreconditions:
			fmt.Fprintln(w, c(line, colorYellow))
		default:
			fmt.Fprintln(w, line)
		}
	}
	fmt.Fprintln(w)
}

// ---- JSON output ------------------------------------------------------------

type jsonProbe struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

type jsonResult struct {
	Target      string      `json:"target"`
	ScannedAt   string      `json:"scanned_at"`
	DurationMs  int64       `json:"duration_ms"`
	PHPVersion  string      `json:"php_version"`
	PHPStatus   string      `json:"php_status"`
	Probes      []jsonProbe `json:"probes"`
	CanaryToken string      `json:"canary_token,omitempty"`
	CanaryPath  string      `json:"canary_path,omitempty"`
	Verdict     string      `json:"verdict"`
	Severity    string      `json:"severity"`
	Detail      string      `json:"detail"`
	Error       string      `json:"error,omitempty"`
	ExitCode    int         `json:"exit_code"`
}

// WriteJSON writes a JSON array of results to w.
func WriteJSON(w io.Writer, results []checker.ScanResult) error {
	out := make([]jsonResult, len(results))
	for i, r := range results {
		probes := make([]jsonProbe, len(r.Probes))
		for j, p := range r.Probes {
			probes[j] = jsonProbe{Name: p.Name, Passed: p.Passed, Detail: p.Detail}
		}
		out[i] = jsonResult{
			Target:      r.Target,
			ScannedAt:   r.ScannedAt.Format(time.RFC3339),
			DurationMs:  r.Duration.Milliseconds(),
			PHPVersion:  ifEmpty(r.PHPVersion.Raw, "unknown"),
			PHPStatus:   r.PHPVersion.Status.String(),
			Probes:      probes,
			CanaryToken: r.CanaryToken,
			CanaryPath:  r.CanaryPath,
			Verdict:     r.Verdict.String(),
			Severity:    r.Verdict.Severity(),
			Detail:      r.VerdictNote,
			Error:       r.Error,
			ExitCode:    r.ExitCode(),
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// ---- Markdown output --------------------------------------------------------

// WriteMarkdown produces a Markdown report suitable for issue trackers / reports.
func WriteMarkdown(w io.Writer, results []checker.ScanResult) {
	fmt.Fprintln(w, "# php2shell-scanner Report")
	fmt.Fprintf(w, "CVE-2026-109618 / CVE-2026-109619 - Generated %s\n\n", time.Now().Format(time.RFC3339))

	for _, r := range results {
		fmt.Fprintf(w, "## %s\n\n", r.Target)
		fmt.Fprintf(w, "| Field | Value |\n|---|---|\n")
		fmt.Fprintf(w, "| Scanned | %s |\n", r.ScannedAt.Format(time.RFC3339))
		fmt.Fprintf(w, "| Duration | %s |\n", r.Duration.Round(time.Millisecond))
		fmt.Fprintf(w, "| PHP Version | %s |\n", ifEmpty(r.PHPVersion.Raw, "unknown"))
		fmt.Fprintf(w, "| PHP Status | %s |\n", r.PHPVersion.Status)
		fmt.Fprintf(w, "| **Verdict** | **%s** |\n", r.Verdict)
		fmt.Fprintf(w, "| Severity | %s |\n\n", r.Verdict.Severity())

		if r.Error != "" {
			fmt.Fprintf(w, "> ERROR: %s\n\n", r.Error)
			continue
		}

		fmt.Fprintf(w, "### Probes\n\n")
		fmt.Fprintln(w, "| # | Probe | Result | Detail |")
		fmt.Fprintln(w, "|---|---|---|---|")
		for i, p := range r.Probes {
			tick := ":white_check_mark:"
			if !p.Passed {
				tick = ":x:"
			}
			fmt.Fprintf(w, "| %d | `%s` | %s | %s |\n", i+1, p.Name, tick, p.Detail)
		}

		if r.CanaryToken != "" {
			fmt.Fprintf(w, "\n**Canary token**: `%s`", r.CanaryToken)
			if r.CanaryPath != "" {
				fmt.Fprintf(w, "  \n**Session file**: `%s`", r.CanaryPath)
			}
			fmt.Fprintln(w)
		}

		fmt.Fprintf(w, "\n**Detail**: %s\n\n", r.VerdictNote)
		fmt.Fprintf(w, "### Mitigation\n\n")
		fmt.Fprintln(w, "```ini")
		fmt.Fprintln(w, "session.upload_progress.enabled = Off")
		fmt.Fprintln(w, "session.use_only_cookies = On")
		fmt.Fprintln(w, "```")
		fmt.Fprintf(w, "\nPatch PHP to the fixed release for your branch.\n\n")
		fmt.Fprintln(w, "---")
	}
}

// ---- helpers ----------------------------------------------------------------

func versionLabel(s version.Status, noColor bool) string {
	c := func(text string, colors ...color) string {
		if noColor {
			return text
		}
		return col(text, colors...)
	}
	switch s {
	case version.StatusVulnerable:
		return c("[VULNERABLE]", colorRed, colorBold)
	case version.StatusEOL:
		return c("[EOL-VULNERABLE]", colorRed)
	case version.StatusPatched:
		return c("[PATCHED]", colorGreen)
	default:
		return c("[UNKNOWN]", colorYellow)
	}
}

func verdictLabel(v checker.Verdict, noColor bool) string {
	c := func(text string, colors ...color) string {
		if noColor {
			return text
		}
		return col(text, colors...)
	}
	switch v {
	case checker.VerdictConfirmed:
		return c("VULNERABLE (confirmed)", colorRed, colorBold)
	case checker.VerdictLikelyVulnerable:
		return c("LIKELY VULNERABLE", colorRed)
	case checker.VerdictLikelyPatched:
		return c("LIKELY PATCHED", colorGreen)
	case checker.VerdictPreconditions:
		return c("PRECONDITIONS PRESENT", colorYellow)
	default:
		return c("NOT DETECTED", colorGreen)
	}
}

func ifEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
