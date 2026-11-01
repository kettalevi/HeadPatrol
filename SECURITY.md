# Security Policy

## Supported versions

Only the latest release of `headpatrol.php` receives fixes. If you host a public instance, update when new releases come out.

## Reporting a vulnerability

HeadPatrol fetches URLs supplied by users, so we take reports seriously, especially:

- **SSRF bypasses**: any way to make HeadPatrol connect to a loopback, private, link-local or otherwise non-public address (redirects, DNS tricks, IPv6 forms, URL parsing differences…)
- XSS or injection through scanned headers or the URL parameter
- Bypassing the rate limits
- Ways to make HeadPatrol download large amounts of data or hang

Please **do not open a public issue**. Use GitHub's private vulnerability reporting instead: open the repository's **Security** tab and choose **Report a vulnerability**.

Include the PHP and curl versions, the input you used, and what happened. You can expect an acknowledgement within a few days and a fix or a plan within two weeks for confirmed issues. Reporters are credited in the changelog unless they prefer otherwise.

## Scope

In scope: `headpatrol.php` and its behaviour with default configuration.

Out of scope: findings HeadPatrol reports about scanned websites (that is the tool working), and instances where an operator enabled `HEADPATROL_ALLOW_PRIVATE_TARGETS` on an internet-facing server.
