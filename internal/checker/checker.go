// Package checker implements the four non-destructive probes for
// CVE-2026-109618 / CVE-2026-109619.
//
// Probe summary:
//
//  1. Fingerprint  - PHP version from response headers/body
//  2. Fixation     - Is a POST-body PHPSESSID honored (use_only_cookies=Off)?
//  3. UploadProg   - Is PHP_SESSION_UPLOAD_PROGRESS accepted?
//  4. CanaryLFI    - Inject an inert random token via filename; read it back
//     through a caller-supplied LFI endpoint to prove
//     inject+include. No <?php tags, never executes code.
package checker

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/php2shell-scanner/internal/version"
)

// Config holds per-target scan parameters.
type Config struct {
	Target       string // base URL, e.g. http://host:8080
	SessionPath  string // endpoint calling session_start(), default "/"
	LFI          string // optional; FUZZ is replaced with file path
	SavePath     string // optional; session.save_path on the target
	Timeout      time.Duration
	SkipTLS      bool // skip TLS cert verification (authorized testing)
	UserAgent    string
	ExtraHeaders map[string]string
}

// Verdict is the final conclusion for a single target.
type Verdict int

const (
	VerdictNotDetected      Verdict = iota
	VerdictPreconditions            // some flags set, not enough to conclude
	VerdictLikelyPatched            // version at/above fixed release
	VerdictLikelyVulnerable         // preconditions + version, no LFI to confirm
	VerdictConfirmed                // canary injected and read back
)

func (v Verdict) String() string {
	switch v {
	case VerdictConfirmed:
		return "VULNERABLE (confirmed)"
	case VerdictLikelyVulnerable:
		return "LIKELY VULNERABLE"
	case VerdictLikelyPatched:
		return "LIKELY PATCHED"
	case VerdictPreconditions:
		return "PRECONDITIONS PRESENT"
	default:
		return "NOT DETECTED"
	}
}

// Severity returns a short label for reporting/colouring.
func (v Verdict) Severity() string {
	switch v {
	case VerdictConfirmed, VerdictLikelyVulnerable:
		return "HIGH"
	case VerdictPreconditions:
		return "MEDIUM"
	case VerdictLikelyPatched:
		return "INFO"
	default:
		return "INFO"
	}
}

// ProbeResult holds the outcome of one individual probe.
type ProbeResult struct {
	Name    string
	Passed  bool
	Detail  string
	RawData string // extra debug info
}

// ScanResult is the full report for one target.
type ScanResult struct {
	Target      string
	ScannedAt   time.Time
	Duration    time.Duration
	PHPVersion  version.Result
	Probes      []ProbeResult
	CanaryToken string // only set when LFI probe ran
	CanaryPath  string // session file path where canary was found
	Verdict     Verdict
	VerdictNote string
	Error       string // set if scan could not complete
}

// ExitCode maps to the original scanner's exit code contract:
//
//	0 = vulnerable/confirmed, 1 = safe/unclear, 2 = unreachable
func (r *ScanResult) ExitCode() int {
	if r.Error != "" {
		return 2
	}
	if r.Verdict == VerdictConfirmed || r.Verdict == VerdictLikelyVulnerable {
		return 0
	}
	return 1
}

// defaultSavePaths is the candidate list when --save-path is not specified.
var defaultSavePaths = []string{
	"/tmp/sessions",
	"/var/lib/php/sessions",
	"/var/lib/php/session",
	"/var/lib/php5/sessions",
	"/tmp",
}

// setCookieRe extracts the PHPSESSID value from a Set-Cookie header.
var setCookieRe = regexp.MustCompile(`(?i)PHPSESSID=([^;,\s]+)`)

// Scan runs all probes against cfg.Target and returns a ScanResult.
func Scan(cfg Config, sidGen func() string) ScanResult {
	start := time.Now()
	res := ScanResult{
		Target:    cfg.Target,
		ScannedAt: start,
	}

	if cfg.UserAgent == "" {
		cfg.UserAgent = "php2shell-scanner/2.0 (authorized security testing)"
	}

	client := buildClient(cfg)

	// ------------------------------------------------------------------ //
	// Probe 1 - Fingerprint
	// ------------------------------------------------------------------ //
	fpProbe := ProbeResult{Name: "fingerprint"}
	status, headers, body, err := get(client, cfg.Target, cfg.UserAgent, cfg.ExtraHeaders)
	if err != nil {
		res.Error = fmt.Sprintf("target unreachable: %v", err)
		fpProbe.Detail = res.Error
		res.Probes = append(res.Probes, fpProbe)
		res.Verdict = VerdictNotDetected
		res.Duration = time.Since(start)
		return res
	}

	banner := headers.Get("X-Powered-By")
	if banner == "" {
		banner = headers.Get("Server")
	}
	rawVer := version.ExtractFromBanner(banner, string(body))
	res.PHPVersion = version.Classify(rawVer)

	fpProbe.Passed = res.PHPVersion.Status == version.StatusVulnerable ||
		res.PHPVersion.Status == version.StatusEOL
	fpProbe.Detail = fmt.Sprintf("PHP %s -> %s | %s | HTTP %d",
		ifEmpty(rawVer, "?"), res.PHPVersion.Status, res.PHPVersion.Note, status)
	fpProbe.RawData = fmt.Sprintf("banner=%q", banner)
	res.Probes = append(res.Probes, fpProbe)

	// ------------------------------------------------------------------ //
	// Probe 2 - Session fixation (POST-body PHPSESSID honored?)
	// ------------------------------------------------------------------ //
	fixProbe := ProbeResult{Name: "fixation"}
	sidFix := sidGen()
	upResp, err := uploadProgressPOST(client, cfg, sidFix, "canary.txt", false)
	if err != nil {
		fixProbe.Detail = fmt.Sprintf("connection error: %v", err)
	} else {
		// If the server echoes back the SID we sent (not issuing a new one), fixation works.
		setCk := upResp.setcookie
		issuedNew := setCookieRe.MatchString(setCk) && !strings.Contains(setCk, sidFix)
		fixProbe.Passed = upResp.ok && !issuedNew
		fixProbe.Detail = fmt.Sprintf("POST-body PHPSESSID %s | HTTP %d",
			boolLabel(fixProbe.Passed, "honored (use_only_cookies=Off)", "NOT honored"),
			upResp.status)
		fixProbe.RawData = fmt.Sprintf("Set-Cookie: %s", setCk)
	}
	res.Probes = append(res.Probes, fixProbe)

	// ------------------------------------------------------------------ //
	// Probe 3 - upload_progress accepted (not disabled / WAF-blocked)
	// ------------------------------------------------------------------ //
	upProbe := ProbeResult{Name: "upload_progress"}
	sidUp := sidGen()
	upResp2, err := uploadProgressPOST(client, cfg, sidUp, "probe.txt", true)
	if err != nil {
		upProbe.Detail = fmt.Sprintf("connection error: %v", err)
	} else {
		upProbe.Passed = upResp2.ok
		upProbe.Detail = fmt.Sprintf("multipart probe -> HTTP %d %s",
			upResp2.status,
			boolLabel(upProbe.Passed, "(accepted)", "(blocked/rejected)"))
		upProbe.RawData = fmt.Sprintf("status_line=%q", upResp2.statusLine)
	}
	res.Probes = append(res.Probes, upProbe)

	// ------------------------------------------------------------------ //
	// Probe 4 - Inert canary LFI confirmation (optional)
	// ------------------------------------------------------------------ //
	lfiProbe := ProbeResult{Name: "canary_lfi"}
	if cfg.LFI != "" {
		canary := "P2S_" + sidGen() // no <?php tags - inert token
		res.CanaryToken = canary
		sidCan := sidGen()

		_, injErr := uploadProgressPOST(client, cfg, sidCan, canary, true)
		if injErr != nil {
			lfiProbe.Detail = fmt.Sprintf("inject error: %v", injErr)
		} else {
			candidates := defaultSavePaths
			if cfg.SavePath != "" {
				candidates = append([]string{cfg.SavePath}, candidates...)
			}
			for _, base := range candidates {
				sessFile := strings.TrimRight(base, "/") + "/sess_" + sidCan
				lfiBody, lfiErr := lfiRead(client, cfg.LFI, sessFile, cfg.UserAgent)
				if lfiErr == nil && bytes.Contains(lfiBody, []byte(canary)) {
					lfiProbe.Passed = true
					lfiProbe.Detail = fmt.Sprintf("canary read back from %s", sessFile)
					res.CanaryPath = sessFile
					break
				}
			}
			if !lfiProbe.Passed {
				lfiProbe.Detail = "canary not found (wrong --save-path, no LFI, or injection blocked)"
			}
		}
	} else {
		lfiProbe.Detail = "skipped (pass --lfi to prove inject+include primitive)"
	}
	res.Probes = append(res.Probes, lfiProbe)

	// ------------------------------------------------------------------ //
	// Final verdict
	// ------------------------------------------------------------------ //
	versionVuln := res.PHPVersion.Status == version.StatusVulnerable ||
		res.PHPVersion.Status == version.StatusEOL

	switch {
	case lfiProbe.Passed:
		res.Verdict = VerdictConfirmed
		res.VerdictNote = "injection+inclusion primitive proven with an inert canary (no code executed)."

	case versionVuln && fixProbe.Passed && upProbe.Passed:
		res.Verdict = VerdictLikelyVulnerable
		res.VerdictNote = "affected version + session fixation + upload_progress all present; " +
			"supply --lfi to confirm end-to-end."

	case res.PHPVersion.Status == version.StatusPatched:
		res.Verdict = VerdictLikelyPatched
		res.VerdictNote = "PHP version is at or above the fixed release for its branch."

	case fixProbe.Passed || upProbe.Passed:
		res.Verdict = VerdictPreconditions
		res.VerdictNote = "some preconditions hold; version unclear or one check failed."

	default:
		res.Verdict = VerdictNotDetected
		res.VerdictNote = "no preconditions observed."
	}

	res.Duration = time.Since(start)
	return res
}

// ---- HTTP helpers -----------------------------------------------------------

type upResponse struct {
	ok         bool
	status     int
	statusLine string
	setcookie  string
	body       []byte
}

// uploadProgressPOST sends a multipart POST with PHP_SESSION_UPLOAD_PROGRESS.
// The PHPSESSID is always put in the POST body (fixation probe).
// When sendCookie is true the sid is also sent as a Cookie header.
func uploadProgressPOST(client *http.Client, cfg Config, sid, filename string, sendCookie bool) (upResponse, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	// POST-body PHPSESSID (session fixation test)
	_ = mw.WriteField("PHPSESSID", sid)
	// upload_progress key
	_ = mw.WriteField("PHP_SESSION_UPLOAD_PROGRESS", "x")
	// The "file" whose filename is the injection point
	fw, _ := mw.CreateFormFile("f", filename)
	_, _ = fw.Write([]byte("Z"))
	mw.Close()

	targetURL := strings.TrimRight(cfg.Target, "/") + cfg.SessionPath
	req, err := http.NewRequest(http.MethodPost, targetURL, &buf)
	if err != nil {
		return upResponse{}, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("User-Agent", cfg.UserAgent)
	for k, v := range cfg.ExtraHeaders {
		req.Header.Set(k, v)
	}
	if sendCookie {
		req.AddCookie(&http.Cookie{Name: "PHPSESSID", Value: sid})
	}

	resp, err := client.Do(req)
	if err != nil {
		return upResponse{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))

	setCk := ""
	for _, ck := range resp.Cookies() {
		if strings.EqualFold(ck.Name, "PHPSESSID") {
			setCk = fmt.Sprintf("PHPSESSID=%s", ck.Value)
		}
	}

	return upResponse{
		ok:         resp.StatusCode < 500,
		status:     resp.StatusCode,
		statusLine: resp.Status,
		setcookie:  setCk,
		body:       body,
	}, nil
}

// get performs a plain GET and returns (status, headers, body, error).
func get(client *http.Client, target, ua string, extra map[string]string) (int, http.Header, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("User-Agent", ua)
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	return resp.StatusCode, resp.Header, body, nil
}

// lfiRead fetches the LFI endpoint with FUZZ replaced.
func lfiRead(client *http.Client, lfiTemplate, filePath, ua string) ([]byte, error) {
	u := strings.ReplaceAll(lfiTemplate, "FUZZ", url.QueryEscape(filePath))
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ua)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 262144))
}

func buildClient(cfg Config) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: cfg.SkipTLS}, //nolint:gosec
		DisableKeepAlives: true,
	}
	return &http.Client{
		Timeout:   cfg.Timeout,
		Transport: tr,
	}
}

// ---- tiny helpers -----------------------------------------------------------

func ifEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func boolLabel(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}
