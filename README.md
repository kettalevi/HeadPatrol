# HeadPatrol

**Patrol any site's security headers. One file. No install. Real fixes.**

[![CI](https://github.com/kettalevi/HeadPatrol/actions/workflows/ci.yml/badge.svg)](https://github.com/kettalevi/HeadPatrol/actions/workflows/ci.yml)
![PHP 7.0–8.5](https://img.shields.io/badge/PHP-7.0%E2%80%938.5-777BB4)
![Dependencies: none](https://img.shields.io/badge/dependencies-none-brightgreen)
![SSRF hardened](https://img.shields.io/badge/SSRF-hardened-0f766e)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

HeadPatrol scans any website and grades its HTTP security headers, Content Security Policy, cookies, CORS and HTTPS setup. Then it hands you the **exact configuration to fix them** for Apache, nginx, PHP, IIS and Netlify / Cloudflare Pages.

It's a single PHP file. Upload it to any host and you have your own security headers scanner, or run it from the command line and in CI.

![HeadPatrol report](docs/screenshot.png)

## Why HeadPatrol?

Most header checkers stop at "header present: yes/no". HeadPatrol goes further:

- **Real CSP analysis.** It flags `'unsafe-inline'` without nonces, wildcard sources (`*`, `https:`, `data:`), `'unsafe-eval'`, missing `object-src 'none'` and `base-uri`, and Report-Only policies that block nothing. It also understands `'strict-dynamic'` and nonces the way browsers do.
- **Cookie audit.** Every `Set-Cookie` is checked for `Secure`, `HttpOnly` and `SameSite`, with stricter rules for cookies that look like sessions or tokens. Cookie values are never displayed.
- **CORS misconfiguration detection.** HeadPatrol sends a made-up `Origin` and catches servers that reflect any origin, which is especially dangerous when combined with `Access-Control-Allow-Credentials: true`.
- **HTTPS end to end.** It checks certificate validity, whether plain HTTP permanently redirects to HTTPS (following the full chain), and the HSTS `max-age`, `includeSubDomains` and `preload` settings.
- **Copy-paste fixes.** Every missing header is generated for 5 platforms in one click.
- **Self-hostable and private.** Your scans never touch a third-party service.
- **Built to be safely public.** See [Security model](#security-model).

## Quick start

### Host it (web)

1. Download [`headpatrol.php`](https://raw.githubusercontent.com/kettalevi/HeadPatrol/main/headpatrol.php):
   ```bash
   curl -O https://raw.githubusercontent.com/kettalevi/HeadPatrol/main/headpatrol.php
   ```
2. Upload it to any PHP 7.0+ host with the `curl` extension (almost all have it). Rename it to `index.php` in its own folder if you like.
3. Open it in your browser and scan a site.

Results have shareable links (`?url=example.com`), and every scan is also available as JSON:

```
https://your-host/headpatrol.php?url=example.com&format=json
```

### Command line

```bash
php headpatrol.php example.com
php headpatrol.php https://example.com https://example.org      # several sites
php headpatrol.php --json example.com > report.json
php headpatrol.php --fail-on=medium https://staging.example.com  # CI gate
```

| Option | Meaning |
| --- | --- |
| `--json` | JSON output (an array when several URLs are given) |
| `--fail-on=LEVEL` | Exit 1 if a failed check is at least `high` (default), `medium`, `low`; `none` never fails |
| `--no-color` | Plain output (also honours `NO_COLOR`) |
| `--allow-private` | Allow private/internal addresses, for auditing your own intranet |
| `--proxy=URL` | Send requests through an HTTP proxy |
| `--cacert=FILE` | Extra CA bundle for TLS verification |

Exit codes: `0` OK · `1` failed checks at the `--fail-on` level · `2` usage error · `3` scan error.

### In CI (GitHub Actions)

```yaml
- name: Check security headers
  run: |
    curl -sO https://raw.githubusercontent.com/kettalevi/HeadPatrol/main/headpatrol.php
    php headpatrol.php --fail-on=medium https://staging.example.com
```

## What it checks

| Area | Checks |
| --- | --- |
| **Transport security** | Served over HTTPS · valid TLS certificate · HTTP → HTTPS redirect (permanent, followed to the end) · HSTS presence, `max-age`, `includeSubDomains`, `preload` |
| **Content Security Policy** | Enforced vs Report-Only · scripts restricted · `'unsafe-inline'` without nonce/hash · wildcard and `http:` sources · `'unsafe-eval'` · `object-src 'none'` · `base-uri` |
| **Browser protections** | Clickjacking (`X-Frame-Options` / `frame-ancestors`) · `X-Content-Type-Options` · `Referrer-Policy` · `Permissions-Policy` · `Cross-Origin-Opener-Policy` |
| **CORS** | Reflected origins · reflected origins with credentials · `null` origin · `*` |
| **Cookies** | `Secure` · `HttpOnly` (strict for session/auth cookies) · `SameSite` · `SameSite=None` without `Secure` · `__Host-` / `__Secure-` prefixes |
| **Information disclosure** | Versions in `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator` and more |
| **Deprecated headers** | `X-XSS-Protection` enabled · `Public-Key-Pins` · `Expect-CT` |

### Scoring

Each failed check costs points by severity (high 15, medium 7, low 3); warnings cost half and informational notes cost nothing. The score maps to a grade: **A+** (perfect, no warnings), **A** ≥ 90, **B** ≥ 80, **C** ≥ 70, **D** ≥ 60, otherwise **F**.

## Security model

A tool that fetches URLs typed by strangers is a classic target for **Server-Side Request Forgery (SSRF)**: tricking your server into requesting `http://localhost`, internal admin panels, or cloud metadata endpoints that hold credentials. HeadPatrol is built to be safe even on a public server:

| Attack | Defence |
| --- | --- |
| `file://`, `gopher://`, `dict://`, `php://`… | Only `http` and `https` are accepted, both when parsing and at the curl protocol level |
| `http://127.0.0.1`, `http://10.0.0.5`, `http://169.254.169.254` | Every resolved IPv4 **and** IPv6 address must be globally routable. Loopback, private, link-local (cloud metadata), CGNAT, multicast, documentation, benchmarking and reserved ranges are refused |
| A domain that points to an internal IP | DNS is resolved and checked **before** connecting. If *any* address is private, the scan is refused |
| DNS rebinding (a domain whose answer changes between check and connect) | The connection is **pinned** to the vetted IP with `CURLOPT_RESOLVE`, and the IP actually connected to is checked again afterwards |
| Redirect to an internal address | Redirects are followed manually and **every hop is re-validated**, up to 5 hops |
| `http://2130706433/`, `0x7f.1`, `0177.0.0.1`, `127.1` | Non-standard numeric host formats are rejected outright |
| `::ffff:127.0.0.1`, `::127.0.0.1`, 6to4, Teredo, NAT64 | IPv4-mapped/compatible addresses are judged by the embedded IPv4; tunnelling ranges are refused |
| `http://user:pass@host`, backslash tricks, CRLF injection | Rejected during URL validation |
| Internal services on other ports (Redis 6379, SSH 22…) | Only ports 80 and 443 are allowed by default |
| Environment proxies that can reach the internal network | Proxies are disabled in web mode |
| Huge or slow responses | 5 s connect / 12 s total timeout; the body is never downloaded; headers are capped at 64 KB |
| Using your server to flood others | Per-IP and global rate limits (10 per IP and 120 total per minute by default) |
| XSS through scanned headers | All output is escaped, non-printable bytes are neutralised, and the page runs under a strict nonce-based CSP |

These defences are covered by more than 130 automated tests ([`tests/run.php`](tests/run.php)) that throw known SSRF bypass tricks at the validator, plus integration tests against a live fixture server. CI runs them on every PHP version from 7.0 to 8.5.

### Configuration

Edit the constants at the top of `headpatrol.php`, or define them in a small wrapper file before including it:

```php
<?php // index.php
define('HEADPATROL_RATE_LIMIT_PER_IP', 5);
define('HEADPATROL_CLIENT_IP_HEADER', 'HTTP_CF_CONNECTING_IP'); // behind Cloudflare
require __DIR__ . '/headpatrol.php';
```

| Constant | Default | Purpose |
| --- | --- | --- |
| `HEADPATROL_RATE_LIMIT_PER_IP` | `10` | Scans per visitor IP per minute |
| `HEADPATROL_RATE_LIMIT_GLOBAL` | `120` | Scans per minute across all visitors |
| `HEADPATROL_ALLOWED_PORTS` | `'80,443'` | Ports scanned URLs may use |
| `HEADPATROL_MAX_REDIRECTS` | `5` | Redirect hops followed (each re-validated) |
| `HEADPATROL_CLIENT_IP_HEADER` | `''` | `$_SERVER` key with the real visitor IP behind a proxy/CDN. Only set it if you are behind one, or visitors can spoof it |
| `HEADPATROL_ALLOW_PRIVATE_TARGETS` | `false` | Allow internal addresses. **Never enable on an internet-facing instance** |

Rate-limit state is stored in the system temp directory, and nothing else is ever written to disk. Scans are not logged or stored.

## Privacy

HeadPatrol reads only the **response headers** of the page you scan. It aborts as soon as the body starts, so page content is never downloaded. It stores nothing about scans, and cookie values are masked in all output. Requests identify themselves honestly with the User-Agent `HeadPatrol/1.0.0 (+https://github.com/kettalevi/HeadPatrol)`.

## Running the tests

```bash
php tests/run.php                                   # unit tests, no network needed
php -S 127.0.0.1:8099 tests/fixture/router.php &    # fixture server
php tests/integration.php                           # end-to-end tests
```

## Part of the Patrol family

- **[PHPatrol](https://github.com/kettalevi/PHPatrol)** checks your PHP server's configuration from the inside.
- **HeadPatrol** checks any website's security headers from the outside.

## Contributing

New checks, false-positive reports and better fix snippets are all welcome. Please keep it to **one file, no dependencies, PHP 7.0+**, and add a test for any new check. Security issues in HeadPatrol itself go through [SECURITY.md](SECURITY.md), not public issues.

## License

[MIT](LICENSE) © Martin Levi K.A
