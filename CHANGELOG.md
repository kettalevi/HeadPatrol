# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-02

### Added
- First release: single-file security headers scanner with web UI, JSON API and CLI.
- Checks for HTTPS, TLS certificate, HTTP→HTTPS redirect, HSTS, Content Security Policy (deep analysis), clickjacking, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Cross-Origin-Opener-Policy, CORS reflection, cookie flags, version disclosure and deprecated headers.
- Copy-paste fixes for Apache, nginx, PHP, IIS and Netlify / Cloudflare Pages.
- SSRF hardening: scheme and port allow-lists, IPv4/IPv6 private-range blocking, DNS pinning, per-hop redirect validation, numeric-host rejection, timeouts and size caps.
- Per-IP and global rate limiting.
- Test suite with SSRF bypass cases, analyser tests and integration tests; CI on PHP 7.0–8.5.
