// php2shell-scanner - CVE-2026-109618 / CVE-2026-109619 validator.
//
// Non-destructive. Never executes code on the target. For authorized
// security testing only.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/alham-rizvi/php2shell-scanner/internal/checker"
	"github.com/alham-rizvi/php2shell-scanner/internal/report"
)

const version = "2.0.0"

func main() {
	os.Exit(run())
}

func run() int {
	// ---- flags ---------------------------------------------------------------
	fTarget := flag.String("target", "", "Target URL, e.g. http://host:8080")
	fTargets := flag.String("targets", "", "File with one target URL per line")
	fSessionPath := flag.String("session-path", "/", "Endpoint that calls session_start()")
	fLFI := flag.String("lfi", "", "LFI endpoint with FUZZ marker, e.g. http://h/vuln.php?page=FUZZ")
	fSavePath := flag.String("save-path", "", "session.save_path on the target")
	fTimeout := flag.Duration("timeout", 10*time.Second, "HTTP timeout per request")
	fConcurrency := flag.Int("concurrency", 5, "Parallel scans (batch mode)")
	fSkipTLS := flag.Bool("skip-tls", false, "Skip TLS certificate verification")
	fNoColor := flag.Bool("no-color", false, "Disable ANSI color output")
	fFormat := flag.String("format", "terminal", "Output format: terminal | json | markdown")
	fOutput := flag.String("output", "", "Write report to file (default: stdout)")
	fUA := flag.String("user-agent", "", "Custom User-Agent string")
	fHeader := flag.String("header", "", "Extra header(s), format: 'Name: Value' (comma-separated for multiple)")
	fVerbose := flag.Bool("verbose", false, "Show raw probe data")
	fYes := flag.Bool("yes", false, "Confirm you are authorized to test this target")
	fVersion := flag.Bool("version", false, "Print version and exit")

	flag.Usage = usage
	flag.Parse()

	if *fVersion {
		fmt.Printf("php2shell-scanner v%s\n", version)
		return 0
	}

	// ---- banner + auth gate --------------------------------------------------
	noColor := *fNoColor || !isTerminal()
	if *fFormat == "terminal" {
		report.PrintBanner(os.Stderr, noColor)
	}

	if !*fYes {
		fmt.Fprintln(os.Stderr, col("  [!] Refusing to run without --yes", 33))
		fmt.Fprintln(os.Stderr, "      Only scan systems you own or have explicit written permission to test.")
		fmt.Fprintln(os.Stderr, "      Re-run with --yes to acknowledge.")
		return 2
	}

	// ---- collect targets -----------------------------------------------------
	var targets []string
	if *fTarget != "" {
		targets = append(targets, *fTarget)
	}
	if *fTargets != "" {
		lines, err := readLines(*fTargets)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [!] Cannot read targets file: %v\n", err)
			return 2
		}
		targets = append(targets, lines...)
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "  [!] Specify --target or --targets")
		usage()
		return 2
	}

	// ---- parse extra headers -------------------------------------------------
	extraHeaders := map[string]string{}
	if *fHeader != "" {
		for _, h := range strings.Split(*fHeader, ",") {
			parts := strings.SplitN(strings.TrimSpace(h), ":", 2)
			if len(parts) == 2 {
				extraHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	// ---- run scans -----------------------------------------------------------
	cfg := checker.Config{
		SessionPath:  *fSessionPath,
		LFI:          *fLFI,
		SavePath:     *fSavePath,
		Timeout:      *fTimeout,
		SkipTLS:      *fSkipTLS,
		UserAgent:    *fUA,
		ExtraHeaders: extraHeaders,
	}

	results := scanTargets(targets, cfg, *fConcurrency, os.Stderr, noColor, *fVerbose)

	// ---- output --------------------------------------------------------------
	var out io.Writer = os.Stdout
	if *fOutput != "" {
		f, err := os.Create(*fOutput)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [!] Cannot create output file: %v\n", err)
			return 2
		}
		defer f.Close()
		out = f
	}

	switch *fFormat {
	case "json":
		if err := report.WriteJSON(out, results); err != nil {
			fmt.Fprintf(os.Stderr, "  [!] JSON encode error: %v\n", err)
			return 2
		}
	case "markdown":
		report.WriteMarkdown(out, results)
	default:
		for _, r := range results {
			report.PrintResult(out, r, noColor)
		}
		if len(results) > 1 {
			report.PrintMultiSummary(out, results, noColor)
		}
	}

	// ---- exit code: worst-case across all targets ----------------------------
	worst := 1
	for _, r := range results {
		if code := r.ExitCode(); code < worst {
			worst = code
		}
	}
	return worst
}

// scanTargets runs scans concurrently and preserves input order in results.
func scanTargets(targets []string, baseCfg checker.Config, concurrency int, statusW *os.File, noColor, verbose bool) []checker.ScanResult {
	if concurrency < 1 {
		concurrency = 1
	}

	type indexed struct {
		idx int
		res checker.ScanResult
	}

	sem := make(chan struct{}, concurrency)
	out := make(chan indexed, len(targets))
	var wg sync.WaitGroup

	for i, t := range targets {
		wg.Add(1)
		go func(idx int, target string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			cfg := baseCfg
			cfg.Target = target

			if len(targets) > 1 {
				fmt.Fprintf(statusW, "%s Scanning %s ...\n",
					col("[*]", 36), target)
			}

			res := checker.Scan(cfg, randomHex)

			if verbose {
				for _, p := range res.Probes {
					if p.RawData != "" {
						fmt.Fprintf(statusW, "    %s %s: %s\n",
							col("[dbg]", 90), p.Name, p.RawData)
					}
				}
			}

			out <- indexed{idx: idx, res: res}
		}(i, t)
	}

	wg.Wait()
	close(out)

	results := make([]checker.ScanResult, len(targets))
	for item := range out {
		results[item.idx] = item.res
	}
	return results
}

// ---- helpers ----------------------------------------------------------------

func randomHex() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, sc.Err()
}

func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func col(text string, ansiCode int) string {
	return fmt.Sprintf("\033[%dm%s\033[0m", ansiCode, text)
}

func usage() {
	fmt.Fprintf(os.Stderr, `
php2shell-scanner v%s
Non-destructive validator for CVE-2026-109618 / CVE-2026-109619
(PHP session.upload_progress filename injection chain)

USAGE:
  php2shell-scanner --target <URL> [options]
  php2shell-scanner --targets <file> [options]

TARGET OPTIONS:
  --target <URL>          Single target, e.g. http://host:8080
  --targets <file>        File of URLs (one per line; # = comment)
  --session-path <path>   Endpoint calling session_start() (default: /)
  --lfi <URL>             LFI endpoint with FUZZ marker
                            e.g. http://h/vuln.php?page=FUZZ
                            Enables check 4 (canary inject+include proof)
  --save-path <path>      session.save_path on the target
                            (default: tries common candidate paths)

HTTP OPTIONS:
  --timeout <duration>    Request timeout (default: 10s)
  --skip-tls              Skip TLS certificate verification
  --user-agent <str>      Custom User-Agent
  --header <str>          Extra header(s): "Name: Value"
                            Multiple: --header "X-A: 1,X-B: 2"

OUTPUT OPTIONS:
  --format <fmt>          terminal | json | markdown  (default: terminal)
  --output <file>         Write report to file
  --no-color              Disable ANSI color output
  --verbose               Show raw probe debug data

BATCH OPTIONS:
  --concurrency <n>       Parallel scans when using --targets (default: 5)

REQUIRED:
  --yes                   Acknowledge you are authorized to test the target

EXIT CODES:
  0 = vulnerable / confirmed vulnerable
  1 = patched / not detected
  2 = unreachable / usage error

EXAMPLES:
  # Preconditions only
  php2shell-scanner --target http://host:8080 --yes

  # Full end-to-end confirmation
  php2shell-scanner --target http://host:8080 \
    --lfi 'http://host:8080/vuln.php?page=FUZZ' \
    --save-path /tmp/sessions \
    --yes

  # Batch scan with JSON output
  php2shell-scanner --targets urls.txt --concurrency 10 --format json --output report.json --yes

  # Markdown report for a bug report
  php2shell-scanner --target http://host:8080 --lfi '...' --format markdown --output report.md --yes

DISCLAIMER:
  For authorized security testing and educational use only.
  Do not scan systems you do not own or lack explicit written permission to test.

`, version)
}
