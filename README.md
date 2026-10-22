<div align="center">

```
+---------------------------------------+
|           php2shell-scanner           |
| PHP session upload_progress validator |
|   CVE-2026-109618 / CVE-2026-109619   |
+---------------------------------------+
```

**Non-destructive validator for CVE-2026-109618 / CVE-2026-109619**
PHP `session.upload_progress` filename-injection chain

[![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev/)
[![Version](https://img.shields.io/badge/Scanner-v2.0.0-7C3AED?style=for-the-badge&logo=github)](https://github.com/alham-rizvi/php2shell-scanner/releases)
[![CVE Coverage](https://img.shields.io/badge/CVE-2026--109618%20%2F%20109619-DC2626?style=for-the-badge)](https://nvd.nist.gov/)
[![Checks](https://img.shields.io/badge/Checks-go%20test%20%7C%20vet%20%7C%20build-16A34A?style=for-the-badge&logo=githubactions&logoColor=white)](#verify-the-build)
[![Reports](https://img.shields.io/badge/Reports-Terminal%20%7C%20JSON%20%7C%20Markdown-2563EB?style=for-the-badge&logo=markdown&logoColor=white)](#usage)
[![Batch Scanning](https://img.shields.io/badge/Scanning-Batch%20%26%20Concurrent-0891B2?style=for-the-badge)](#usage)
[![Inert Canary](https://img.shields.io/badge/Confirmation-Inert%20Canary-059669?style=for-the-badge)](#how-it-works)
[![Authorized Testing](https://img.shields.io/badge/Use-Authorized%20Testing%20Only-F97316?style=for-the-badge)](#how-it-works)

</div>

---

## Overview

php2shell-scanner is a Go-based PHP2shell scanner, built for security researchers and penetration testers conducting **authorized assessments**.

It validates whether a PHP target is susceptible to the `session.upload_progress` filename injection primitive that underlies CVE-2026-109618 and CVE-2026-109619. It **never executes any code on the target** - confirmation is done by injecting an inert random token (no `<?php` tags) and reading it back via a caller-supplied LFI endpoint.

Single static binary. Zero runtime dependencies. No Python, no pip, no virtualenv.

---

## How It Works

Four sequential, non-destructive probes:

```
[1] fingerprint     PHP version from Server / X-Powered-By headers,
                    mapped to the fixed-release table.

[2] fixation        POST-body PHPSESSID honored?
                    (signals session.use_only_cookies = Off)

[3] upload_progress PHP_SESSION_UPLOAD_PROGRESS multipart key accepted?
                    (not disabled, not WAF-blocked)

[4] canary_lfi      Inject inert token via upload filename.
                    Read back through caller-supplied LFI endpoint.
                    Match proves inject+include primitive.
                    No code ever executes on the target.
```

The canary looks like `P2S_3a9f1c2b...` - a hex string with no PHP tags. Matching it in the session file read-back is proof of the primitive. Swapping the token for `<?php ... ?>` is the step this scanner deliberately omits.

---

## Features at a Glance

| Capability | Included |
|---|---|
| Language | Go 1.22+; single static binary |
| TLS support | Yes, with an explicit `--skip-tls` option |
| Concurrent scanning | Yes, with configurable worker count |
| Batch / multi-target | Yes, using a `--targets` file |
| Output formats | Terminal, JSON, and Markdown |
| Report to file | Yes, with `--output` |
| Custom headers and User-Agent | Yes |
| Verbose probe details | Yes, with `--verbose` |
| Tests | PHP version classifier covered |
| Runtime dependencies | None |
---

## Installation

### Pre-built binary

Download the binary from [Releases](https://github.com/alham-rizvi/php2shell-scanner/releases), then:

```bash
chmod +x php2shell-scanner
./php2shell-scanner --version
```

### Build from source

Requirements: Go 1.22 or later.

```bash
git clone https://github.com/alham-rizvi/php2shell-scanner.git
cd php2shell-scanner
go build -ldflags="-s -w" -o php2shell-scanner ./cmd/php2shell-scanner/
```

### go install

```bash
go install github.com/alham-rizvi/php2shell-scanner/cmd/php2shell-scanner@latest
```

### Verify the build

```bash
go test ./...
go vet ./...
```

---

## Usage

```
USAGE:
  php2shell-scanner --target <URL> [options]
  php2shell-scanner --targets <file> [options]

TARGET OPTIONS:
  --target <URL>          Single target, e.g. http://host:8080
  --targets <file>        File of URLs (one per line; # = comment)
  --session-path <path>   Endpoint calling session_start() (default: /)
  --lfi <URL>             LFI endpoint with FUZZ marker
                            e.g. http://host/vuln.php?page=FUZZ
                            Enables probe 4 (canary inject+include proof)
  --save-path <path>      session.save_path on the target
                            (default: tries common candidate paths)

HTTP OPTIONS:
  --timeout <duration>    Per-request timeout (default: 10s)
  --skip-tls              Skip TLS certificate verification
  --user-agent <str>      Custom User-Agent string
  --header <str>          Extra header(s): "Name: Value"
                            Multiple: --header "X-A: 1,X-B: 2"

OUTPUT OPTIONS:
  --format <fmt>          terminal | json | markdown  (default: terminal)
  --output <file>         Write report to file instead of stdout
  --no-color              Disable ANSI color output
  --verbose               Print raw probe debug data

BATCH OPTIONS:
  --concurrency <n>       Parallel scans when using --targets (default: 5)

REQUIRED:
  --yes                   Acknowledge you are authorized to test this target
  --version               Print version and exit
```

### Examples

```bash
# Preconditions check only (version + fixation + upload_progress)
./php2shell-scanner --target http://host:8080 --yes

# Full end-to-end confirmation with an LFI endpoint
./php2shell-scanner \
  --target http://host:8080 \
  --session-path /index.php \
  --lfi 'http://host:8080/vuln.php?page=FUZZ' \
  --save-path /tmp/sessions \
  --yes

# Batch scan - multiple targets, 10 concurrent workers
./php2shell-scanner \
  --targets urls.txt \
  --concurrency 10 \
  --format json \
  --output report.json \
  --yes

# Markdown report for a bug report or issue tracker
./php2shell-scanner \
  --target http://host:8080 \
  --lfi 'http://host:8080/vuln.php?page=FUZZ' \
  --format markdown \
  --output report.md \
  --yes

# HTTPS target with self-signed cert, custom auth header
./php2shell-scanner \
  --target https://host:443 \
  --skip-tls \
  --header "Authorization: Bearer <token>" \
  --yes
```

### urls.txt format

```
# Lines beginning with # are ignored
http://target-one:8080
http://target-two:8080
https://target-three
```

---

## Verdicts

| Verdict                  | Meaning                                                                 |
|--------------------------|-------------------------------------------------------------------------|
| `VULNERABLE (confirmed)` | Canary injected and read back - inject+include primitive proven         |
| `LIKELY VULNERABLE`      | Affected version + fixation + upload_progress; supply --lfi to confirm  |
| `PRECONDITIONS PRESENT`  | Some signals hold; version unclear or one check failed                  |
| `LIKELY PATCHED`         | PHP version at or above the fixed release for its branch                |
| `NOT DETECTED`           | No preconditions observed                                               |

### Exit codes

| Code | Meaning                              |
|------|--------------------------------------|
| 0    | Vulnerable or confirmed vulnerable   |
| 1    | Patched / not detected               |
| 2    | Unreachable / usage error            |

Exit codes are consistent across single and batch modes (worst-case across all targets).

---

## Fixed Releases

| Branch | Vulnerable below | First patched |
|--------|-----------------|---------------|
| 8.2    | 8.2.35          | 8.2.35        |
| 8.3    | 8.3.36          | 8.3.36        |
| 8.4    | 8.4.27          | 8.4.27        |
| 8.5    | 8.5.12          | 8.5.12        |

Branches 8.1, 8.0, 7.x, and 5.x are end-of-life with no official patch. They are treated as vulnerable wherever `upload_progress` is present.

---

## Mitigation

Add to your `php.ini`:

```ini
session.upload_progress.enabled = Off
session.use_only_cookies = On
```

And patch PHP to the fixed release for your branch.

---

## Project Structure

```
php2shell-scanner/
|- cmd/
|  `- php2shell-scanner/
|     `- main.go              CLI entry point, flag parsing, batch orchestration
|- internal/
|  |- checker/
|  |  `- checker.go           Four probes, HTTP client, verdict logic
|  |- version/
|  |  |- version.go           PHP version classifier, banner extraction
|  |  `- version_test.go      Unit tests
|  `- report/
|     `- report.go            Terminal / JSON / Markdown output formatters
`- go.mod
```

---

## Credits

**Author**
Alham Rizvi ([@alham-rizvi](https://github.com/alham-rizvi))

**CVE References**
- CVE-2026-109618 - PHP session.upload_progress filename injection
- CVE-2026-109619 - PHP session fixation via POST body

**POC Reference**
[ikow/php2shell-poc](https://github.com/ikow/php2shell-poc) - the exploit POC this scanner detects (referenced for testing against the lab environment only).

## Disclaimer

For authorized security testing and educational use only.
Do not scan systems you do not own or lack explicit written permission to test.
The authors accept no liability for misuse.
