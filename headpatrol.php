<?php
/**
 * HeadPatrol — patrol any site's security headers.
 * One file. No install. Real fixes.
 * https://github.com/kettalevi/HeadPatrol
 *
 * Scans a website's HTTP response and grades its security headers, Content
 * Security Policy, cookies, CORS, HTTPS setup and information leaks, then
 * generates ready-to-paste configuration for Apache, nginx, PHP, IIS and
 * Netlify / Cloudflare Pages.
 *
 * Web:  upload to any PHP host and open it in a browser.
 * CLI:  php headpatrol.php https://example.com [--json] [--fail-on=high|medium|low|none]
 *
 * The fetcher is hardened against SSRF: http/https only, allow-listed ports,
 * no credentials in URLs, every DNS answer checked against private/reserved
 * ranges, the connection pinned to the checked IP (no DNS rebinding), every
 * redirect re-validated, strict timeouts and size caps, and per-IP rate limits.
 *
 * Runs on PHP 7.0 and newer with the curl extension.
 * License: MIT
 */

// ============================================================================
//  CONFIGURATION
// ============================================================================

// Scans allowed per visitor IP per minute (web mode).
if (!defined('HEADPATROL_RATE_LIMIT_PER_IP')) define('HEADPATROL_RATE_LIMIT_PER_IP', 10);

// Scans allowed in total per minute across all visitors (web mode).
if (!defined('HEADPATROL_RATE_LIMIT_GLOBAL')) define('HEADPATROL_RATE_LIMIT_GLOBAL', 120);

// Ports a scanned URL may use. Keep this short on a public instance.
if (!defined('HEADPATROL_ALLOWED_PORTS')) define('HEADPATROL_ALLOWED_PORTS', '80,443');

// Maximum redirects followed. Each hop is validated again.
if (!defined('HEADPATROL_MAX_REDIRECTS')) define('HEADPATROL_MAX_REDIRECTS', 5);

// DANGER: allow scanning private/internal addresses (10.x, 192.168.x, localhost...).
// Only for an instance that is NOT reachable from the internet (e.g. auditing an intranet).
if (!defined('HEADPATROL_ALLOW_PRIVATE_TARGETS')) define('HEADPATROL_ALLOW_PRIVATE_TARGETS', false);

// If HeadPatrol sits behind a reverse proxy / CDN, the $_SERVER key that holds the real
// visitor IP, e.g. 'HTTP_CF_CONNECTING_IP' (Cloudflare) or 'HTTP_X_REAL_IP'.
// Leave empty unless you are sure: a wrong value lets visitors spoof their IP and dodge rate limits.
if (!defined('HEADPATROL_CLIENT_IP_HEADER')) define('HEADPATROL_CLIENT_IP_HEADER', '');

// ============================================================================

define('HEADPATROL_VERSION', '1.0.0');
define('HEADPATROL_URL', 'https://github.com/kettalevi/HeadPatrol');
define('HEADPATROL_PROBE_ORIGIN', 'https://cors-probe.headpatrol.invalid');
define('HEADPATROL_IS_CLI', PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg');

// ----------------------------------------------------------------------------
//  Small helpers
// ----------------------------------------------------------------------------

function hp_h($s)
{
    return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/** Keep header text printable ASCII so it is safe to display and JSON-encode. */
function hp_clean($s, $max = 4000)
{
    $s = preg_replace('/[^\x20-\x7E\t]/', '?', (string)$s);
    return strlen($s) > $max ? substr($s, 0, $max) . '…' : $s;
}

function hp_allowed_ports()
{
    return array_map('intval', array_filter(array_map('trim', explode(',', HEADPATROL_ALLOWED_PORTS))));
}

// ----------------------------------------------------------------------------
//  SSRF protection: address classification
// ----------------------------------------------------------------------------

function hp_ip_in_cidr($ip, $cidr)
{
    $parts = explode('/', $cidr, 2);
    $a = @inet_pton($ip);
    $b = @inet_pton($parts[0]);
    if ($a === false || $b === false || strlen($a) !== strlen($b)) {
        return false;
    }
    $bits = isset($parts[1]) ? (int)$parts[1] : strlen($a) * 8;
    $bytes = intdiv($bits, 8);
    if ($bytes > 0 && substr($a, 0, $bytes) !== substr($b, 0, $bytes)) {
        return false;
    }
    $rem = $bits % 8;
    if ($rem === 0) {
        return true;
    }
    $mask = (0xFF << (8 - $rem)) & 0xFF;
    return (ord($a[$bytes]) & $mask) === (ord($b[$bytes]) & $mask);
}

/**
 * True only for globally routable unicast addresses.
 * Everything else (loopback, private, link-local incl. cloud metadata, CGNAT,
 * multicast, documentation, benchmarking, reserved...) is refused.
 */
function hp_ip_is_public($ip)
{
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $blocked = array(
            '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
            '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.31.196.0/24', '192.52.193.0/24',
            '192.88.99.0/24', '192.168.0.0/16', '192.175.48.0/24', '198.18.0.0/15',
            '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
        );
        foreach ($blocked as $c) {
            if (hp_ip_in_cidr($ip, $c)) {
                return false;
            }
        }
        return true;
    }
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        $bin = inet_pton($ip);
        // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d): judge the embedded IPv4.
        if (substr($bin, 0, 10) === str_repeat("\0", 10) && (substr($bin, 10, 2) === "\xff\xff" || substr($bin, 10, 2) === "\0\0")) {
            $v4 = inet_ntop(substr($bin, 12));
            return $v4 !== false && hp_ip_is_public($v4);
        }
        // Only global unicast (2000::/3) is acceptable...
        if (!hp_ip_in_cidr($ip, '2000::/3')) {
            return false;
        }
        // ...minus special-purpose blocks inside it (Teredo/ORCHID/etc., documentation, 6to4).
        foreach (array('2001::/23', '2001:db8::/32', '2002::/16', '3fff::/20') as $c) {
            if (hp_ip_in_cidr($ip, $c)) {
                return false;
            }
        }
        return true;
    }
    return false;
}

// ----------------------------------------------------------------------------
//  SSRF protection: URL normalisation and DNS
// ----------------------------------------------------------------------------

/**
 * Turn user input into a canonical http(s) URL, or return an error string.
 * @return array|string  ['url','scheme','host','hostfmt','port'] or an error message
 */
function hp_normalize_url($input)
{
    $input = trim((string)$input);
    if ($input === '') {
        return 'Enter a URL to scan.';
    }
    if (strlen($input) > 2048) {
        return 'That URL is too long (2048 characters maximum).';
    }
    if (preg_match('/[\x00-\x20\x7F]/', $input)) {
        return 'URLs cannot contain spaces or control characters.';
    }
    if (!preg_match('#^[a-z][a-z0-9+.\-]*://#i', $input)) {
        if (preg_match('#^[a-z][a-z0-9+.\-]*:#i', $input) && !preg_match('#^[^:/]+:\d+(/|$)#', $input)) {
            return 'Only http:// and https:// URLs can be scanned.';
        }
        $input = 'https://' . ltrim($input, '/');
    }
    if (strpos($input, '\\') !== false) {
        return 'URLs cannot contain backslashes.';
    }
    $p = parse_url($input);
    if ($p === false || empty($p['scheme']) || !isset($p['host']) || $p['host'] === '') {
        return 'That does not look like a valid URL.';
    }
    $scheme = strtolower($p['scheme']);
    if ($scheme !== 'http' && $scheme !== 'https') {
        return 'Only http:// and https:// URLs can be scanned.';
    }
    if (isset($p['user']) || isset($p['pass'])) {
        return 'URLs with a username or password are not allowed.';
    }

    $host = strtolower($p['host']);
    $isV6 = false;
    if ($host[0] === '[') {
        $host = trim($host, '[]');
        if (!filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return 'That IPv6 address is not valid.';
        }
        $isV6 = true;
    } else {
        $host = rtrim($host, '.');
        if (preg_match('/[^\x00-\x7F]/', $host)) {
            if (!function_exists('idn_to_ascii') || !defined('INTL_IDNA_VARIANT_UTS46')) {
                return 'International domain names need the PHP intl extension. Use the punycode form (xn--...) instead.';
            }
            $ascii = @idn_to_ascii($host, 0, INTL_IDNA_VARIANT_UTS46);
            if ($ascii === false || $ascii === '') {
                return 'That domain name is not valid.';
            }
            $host = strtolower($ascii);
        }
        if (!preg_match('/^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$/', $host) || strlen($host) > 253) {
            return 'That domain name is not valid.';
        }
        // Reject numeric hosts that are not a plain dotted IPv4 (e.g. 2130706433, 0x7f.1, 127.1, 0177.0.0.1).
        $numeric = true;
        foreach (explode('.', $host) as $label) {
            if (!preg_match('/^(0x[0-9a-f]*|[0-9]+)$/', $label)) {
                $numeric = false;
                break;
            }
        }
        if ($numeric && !filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return 'Unusual numeric host formats are not allowed. Use a domain name or a normal IPv4 address.';
        }
        if (!$numeric && strpos($host, '.') === false) {
            return 'Enter a full domain name such as example.com.';
        }
    }

    $port = isset($p['port']) ? (int)$p['port'] : ($scheme === 'https' ? 443 : 80);
    if (!in_array($port, hp_allowed_ports(), true)) {
        return 'Port ' . $port . ' is not allowed. Allowed ports: ' . implode(', ', hp_allowed_ports()) . '.';
    }

    $hostfmt = $isV6 ? '[' . $host . ']' : $host;
    $default = ($scheme === 'https' && $port === 443) || ($scheme === 'http' && $port === 80);
    $path = isset($p['path']) && $p['path'] !== '' ? $p['path'] : '/';
    $path = preg_replace_callback('/[^\x21-\x7E]/', function ($m) {
        return rawurlencode($m[0]);
    }, $path);
    $query = isset($p['query']) ? '?' . $p['query'] : '';

    return array(
        'url' => $scheme . '://' . $hostfmt . ($default ? '' : ':' . $port) . $path . $query,
        'scheme' => $scheme, 'host' => $host, 'hostfmt' => $hostfmt, 'port' => $port,
    );
}

/** Resolve a host to all of its IPv4 and IPv6 addresses. */
function hp_resolve($host)
{
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        return array($host);
    }
    $ips = array();
    $v4 = @gethostbynamel($host . '.');
    if (is_array($v4)) {
        $ips = $v4;
    }
    if (function_exists('dns_get_record') && defined('DNS_AAAA')) {
        $recs = @dns_get_record($host . '.', DNS_AAAA);
        if (is_array($recs)) {
            foreach ($recs as $r) {
                if (!empty($r['ipv6'])) {
                    $ips[] = $r['ipv6'];
                }
            }
        }
    }
    return array_values(array_unique($ips));
}

/**
 * Resolve and vet a target. Every address must be public; returns the address
 * to pin the connection to, or an error string.
 */
function hp_vet_target($parts, $allowPrivate)
{
    $ips = hp_resolve($parts['host']);
    if (!$ips) {
        return array('error' => 'Could not resolve ' . $parts['host'] . '. Check the domain name.');
    }
    if (!$allowPrivate) {
        foreach ($ips as $ip) {
            if (!hp_ip_is_public($ip)) {
                return array('error' => $parts['host'] . ' points to a private or reserved address (' . $ip . '). HeadPatrol only scans public websites.');
            }
        }
    }
    $pin = $ips[0];
    foreach ($ips as $ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $pin = $ip;
            break;
        }
    }
    return array('ip' => $pin, 'all' => $ips);
}

/** Resolve a Location header against the URL it came from. */
function hp_resolve_location($base, $loc)
{
    $loc = trim($loc);
    if ($loc === '') {
        return $base;
    }
    if (preg_match('#^[a-z][a-z0-9+.\-]*:#i', $loc)) {
        return $loc;
    }
    $b = parse_url($base);
    if (substr($loc, 0, 2) === '//') {
        return $b['scheme'] . ':' . $loc;
    }
    $origin = $b['scheme'] . '://' . $b['host'] . (isset($b['port']) ? ':' . $b['port'] : '');
    $path = isset($b['path']) ? $b['path'] : '/';
    if ($loc[0] === '/') {
        return $origin . $loc;
    }
    if ($loc[0] === '?') {
        return $origin . $path . $loc;
    }
    if ($loc[0] === '#') {
        return $base;
    }
    return $origin . preg_replace('#/[^/]*$#', '/', $path) . $loc;
}

// ----------------------------------------------------------------------------
//  Hardened fetcher
// ----------------------------------------------------------------------------

/**
 * Fetch one URL (no redirects followed) and return only its status and headers.
 * Options: allow_private (bool), proxy (string, CLI only), cacert (string), insecure (bool)
 */
function hp_fetch($url, $opts)
{
    $out = array('url' => $url, 'status' => 0, 'http_version' => '', 'headers' => array(), 'ip' => '',
        'time_ms' => 0, 'error' => '', 'cert_error' => '');

    $parts = hp_normalize_url($url);
    if (is_string($parts)) {
        $out['error'] = $parts;
        return $out;
    }
    $out['url'] = $parts['url'];
    $allowPrivate = !empty($opts['allow_private']);
    $proxy = isset($opts['proxy']) ? (string)$opts['proxy'] : '';

    $vet = hp_vet_target($parts, $allowPrivate);
    if (isset($vet['error']) && $proxy !== '' && !hp_resolve($parts['host'])) {
        // CLI --proxy mode where only the proxy can resolve names: the proxy decides.
        $vet = array('ip' => '', 'all' => array());
    }
    if (isset($vet['error'])) {
        $out['error'] = $vet['error'];
        return $out;
    }

    $headers = array();
    $status = 0;
    $ver = '';
    $hbytes = 0;
    $tooBig = false;

    $ch = curl_init();
    $set = array(
        CURLOPT_URL => $parts['url'],
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => 12,
        CURLOPT_NOSIGNAL => true,
        CURLOPT_USERAGENT => 'HeadPatrol/' . HEADPATROL_VERSION . ' (+' . HEADPATROL_URL . ')',
        CURLOPT_HTTPHEADER => array(
            'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Origin: ' . HEADPATROL_PROBE_ORIGIN,
        ),
        CURLOPT_SSL_VERIFYPEER => empty($opts['insecure']),
        CURLOPT_SSL_VERIFYHOST => empty($opts['insecure']) ? 2 : 0,
        CURLOPT_HEADERFUNCTION => function ($ch, $line) use (&$headers, &$status, &$ver, &$hbytes, &$tooBig) {
            $len = strlen($line);
            $hbytes += $len;
            if ($hbytes > 65536) {
                $tooBig = true;
                return 0;
            }
            $t = rtrim($line, "\r\n");
            if (preg_match('#^HTTP/(\S+)\s+(\d{3})#', $t, $m)) {
                $headers = array();
                $status = (int)$m[2];
                $ver = $m[1];
            } elseif ($t !== '' && strpos($t, ':') !== false && count($headers) < 300) {
                $kv = explode(':', $t, 2);
                $headers[] = array(hp_clean(trim($kv[0]), 200), hp_clean(trim($kv[1])));
            }
            return $len;
        },
        // We only need headers: abort as soon as the body starts.
        CURLOPT_WRITEFUNCTION => function ($ch, $data) {
            return 0;
        },
    );
    if (defined('CURLOPT_PROTOCOLS')) {
        $set[CURLOPT_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS;
    }
    if (!empty($opts['cacert'])) {
        $set[CURLOPT_CAINFO] = $opts['cacert'];
    }
    if ($proxy !== '') {
        $set[CURLOPT_PROXY] = $proxy;
    } else {
        // Never use an environment proxy, and connect only to the address we vetted.
        $set[CURLOPT_PROXY] = '';
        if (!filter_var($parts['host'], FILTER_VALIDATE_IP)) {
            $pin = strpos($vet['ip'], ':') !== false ? '[' . $vet['ip'] . ']' : $vet['ip'];
            $set[CURLOPT_RESOLVE] = array($parts['host'] . ':' . $parts['port'] . ':' . $pin);
        }
    }
    curl_setopt_array($ch, $set);

    curl_exec($ch);
    $errno = curl_errno($ch);
    $errmsg = curl_error($ch);
    $out['ip'] = (string)curl_getinfo($ch, CURLINFO_PRIMARY_IP);
    $out['time_ms'] = (int)round(curl_getinfo($ch, CURLINFO_TOTAL_TIME) * 1000);
    curl_close($ch);

    // Defence in depth: the address actually used must also be public.
    if ($proxy === '' && !$allowPrivate && $out['ip'] !== '' && !hp_ip_is_public($out['ip'])) {
        $out['error'] = 'Connection went to a private address. Scan refused.';
        return $out;
    }
    if ($tooBig) {
        $out['error'] = 'The server sent more than 64 KB of headers. Scan stopped.';
        return $out;
    }
    if (in_array($errno, array(51, 60), true) && empty($opts['insecure'])) {
        // Invalid certificate: record it, then read the headers without verification.
        $opts['insecure'] = true;
        $retry = hp_fetch($url, $opts);
        $retry['cert_error'] = $errmsg;
        return $retry;
    }
    if ($errno !== 0 && $errno !== 23) { // 23 = we aborted the body on purpose
        $out['error'] = hp_friendly_curl_error($errno, $errmsg);
        return $out;
    }
    if ($status === 0) {
        $out['error'] = 'The server did not send a valid HTTP response.';
        return $out;
    }
    $out['status'] = $status;
    $out['http_version'] = $ver;
    $out['headers'] = $headers;
    return $out;
}

function hp_friendly_curl_error($errno, $msg)
{
    $map = array(
        6 => 'Could not resolve the host name.',
        7 => 'Could not connect to the server (it may be down or blocking connections).',
        28 => 'The server took too long to respond.',
        35 => 'The TLS/SSL handshake failed.',
        47 => 'Too many redirects.',
        52 => 'The server closed the connection without responding.',
        56 => 'The connection was reset while receiving data.',
    );
    return isset($map[$errno]) ? $map[$errno] : 'Request failed: ' . hp_clean($msg, 200);
}

/** Header values by (case-insensitive) name, in order. */
function hp_hget($headers, $name)
{
    $out = array();
    foreach ($headers as $h) {
        if (strcasecmp($h[0], $name) === 0) {
            $out[] = $h[1];
        }
    }
    return $out;
}

/**
 * Full scan: follow redirects safely, probe plain HTTP, analyse the final response.
 * @return array ['error' => string] or the full result
 */
function hp_scan($input, $opts)
{
    if (!function_exists('curl_init')) {
        return array('error' => 'HeadPatrol needs the PHP curl extension, which is not enabled on this server.');
    }
    $start = hp_normalize_url($input);
    if (is_string($start)) {
        return array('error' => $start);
    }

    $chain = array();
    $url = $start['url'];
    $final = null;
    for ($hop = 0; $hop <= HEADPATROL_MAX_REDIRECTS; $hop++) {
        $r = hp_fetch($url, $opts);
        $chain[] = $r;
        if ($r['error'] !== '') {
            return array('error' => ($hop > 0 ? 'Redirect ' . $hop . ' to ' . $r['url'] . ': ' : '') . $r['error'], 'chain' => $chain);
        }
        $loc = hp_hget($r['headers'], 'location');
        if (in_array($r['status'], array(301, 302, 303, 307, 308), true) && $loc) {
            $url = hp_resolve_location($r['url'], $loc[0]);
            continue;
        }
        $final = $r;
        break;
    }
    if ($final === null) {
        return array('error' => 'Stopped after ' . HEADPATROL_MAX_REDIRECTS . ' redirects.', 'chain' => $chain);
    }

    // Does plain HTTP redirect to HTTPS?
    $httpProbe = null;
    if ($start['scheme'] === 'http') {
        $httpProbe = $chain[0];
        $httpProbe['reaches_https'] = stripos($final['url'], 'https://') === 0;
    } elseif (in_array(80, hp_allowed_ports(), true)) {
        $httpProbe = hp_fetch('http://' . $start['hostfmt'] . '/', $opts);
    }

    $report = hp_analyze($final, $chain, $httpProbe);
    $score = max(0, 100 - $report->penalty());
    $counts = $report->counts();
    return array(
        'tool' => 'headpatrol', 'version' => HEADPATROL_VERSION,
        'scanned_at' => gmdate('Y-m-d\TH:i:s\Z'),
        'input' => hp_clean($input, 2048),
        'final_url' => $final['url'], 'status' => $final['status'], 'http_version' => $final['http_version'],
        'ip' => $final['ip'], 'time_ms' => $final['time_ms'],
        'notice' => $final['status'] >= 400
            ? 'This URL returned HTTP ' . $final['status'] . '. Error pages often send different headers from your real pages, so scan a URL that loads normally (HTTP 200) for accurate results.'
            : '',
        'score' => $score, 'grade' => HP_Report::grade($score, $counts), 'counts' => $counts,
        'redirects' => array_map(function ($c) {
            $loc = hp_hget($c['headers'], 'location');
            return array('url' => $c['url'], 'status' => $c['status'], 'location' => $loc ? $loc[0] : '');
        }, $chain),
        'results' => $report->items,
        'recommended_headers' => $report->recommend,
        'headers' => $final['headers'],
    );
}

// ----------------------------------------------------------------------------
//  Report
// ----------------------------------------------------------------------------

class HP_Report
{
    public $items = array();
    public $recommend = array();

    public function add($cat, $id, $title, $status, $sev, $current, $detail, $snippet = '')
    {
        $this->items[] = array('category' => $cat, 'id' => $id, 'title' => $title, 'status' => $status,
            'severity' => $sev, 'current' => (string)$current, 'detail' => $detail, 'snippet' => $snippet);
    }

    public function rec($name, $value)
    {
        $this->recommend[$name] = $value;
    }

    public static function weight($sev)
    {
        $w = array('high' => 15, 'medium' => 7, 'low' => 3);
        return isset($w[$sev]) ? $w[$sev] : 0;
    }

    public function penalty()
    {
        $p = 0;
        foreach ($this->items as $i) {
            if ($i['status'] === 'fail') {
                $p += self::weight($i['severity']);
            } elseif ($i['status'] === 'warn') {
                $p += (int)ceil(self::weight($i['severity']) / 2);
            }
        }
        return $p;
    }

    public function counts()
    {
        $c = array('pass' => 0, 'warn' => 0, 'fail' => 0, 'info' => 0);
        foreach ($this->items as $i) {
            $c[$i['status']]++;
        }
        return $c;
    }

    public static function grade($score, $counts)
    {
        if ($score >= 100 && $counts['fail'] === 0 && $counts['warn'] === 0) return 'A+';
        if ($score >= 90) return 'A';
        if ($score >= 80) return 'B';
        if ($score >= 70) return 'C';
        if ($score >= 60) return 'D';
        return 'F';
    }
}

// ----------------------------------------------------------------------------
//  Analysis
// ----------------------------------------------------------------------------

/** Parse a CSP into [directive => tokens]; the first occurrence of a directive wins. */
function hp_parse_csp($policy)
{
    $d = array();
    foreach (explode(';', $policy) as $part) {
        $tokens = preg_split('/\s+/', trim($part));
        if (!$tokens || $tokens[0] === '') {
            continue;
        }
        $name = strtolower(array_shift($tokens));
        if (!isset($d[$name])) {
            $d[$name] = $tokens;
        }
    }
    return $d;
}

function hp_analyze($final, $chain, $httpProbe)
{
    $r = new HP_Report();
    $h = $final['headers'];
    $https = stripos($final['url'], 'https://') === 0;

    // ---- Transport ---------------------------------------------------------
    $cat = 'Transport security';
    if ($https) {
        $r->add($cat, 'https', 'Served over HTTPS', 'pass', 'high', 'HTTPS', 'Traffic to this page is encrypted.');
        if ($final['cert_error'] !== '' || $chain[0]['cert_error'] !== '') {
            $r->add($cat, 'certificate', 'Valid TLS certificate', 'fail', 'high', $final['cert_error'] ?: $chain[0]['cert_error'],
                'Browsers will show a full-page security warning. The certificate may be expired, self-signed, or for a different domain.',
                'Renew or reissue the certificate (Let\'s Encrypt is free) and make sure the full chain is installed.');
        } else {
            $r->add($cat, 'certificate', 'Valid TLS certificate', 'pass', 'high', 'valid', 'The certificate is trusted and matches the domain.');
        }
    } else {
        $r->add($cat, 'https', 'Served over HTTPS', 'fail', 'high', 'HTTP',
            'The page is served over plain HTTP. Anyone on the network can read and change what visitors see and send.',
            'Install a TLS certificate (free from Let\'s Encrypt) and redirect all HTTP traffic to HTTPS.');
    }

    if ($httpProbe !== null) {
        $loc = hp_hget($httpProbe['headers'], 'location');
        $isRedirect = in_array($httpProbe['status'], array(301, 302, 303, 307, 308), true);
        if ($httpProbe['error'] !== '') {
            $r->add($cat, 'http_redirect', 'HTTP redirects to HTTPS', 'pass', 'medium', 'port 80 not answering',
                'Plain HTTP is not served at all, so it cannot leak traffic.');
        } elseif ($isRedirect && $loc && (isset($httpProbe['reaches_https']) ? $httpProbe['reaches_https'] : stripos(hp_resolve_location($httpProbe['url'], $loc[0]), 'https://') === 0)) {
            $perm = in_array($httpProbe['status'], array(301, 308), true);
            $r->add($cat, 'http_redirect', 'HTTP redirects to HTTPS', $perm ? 'pass' : 'warn', 'low',
                $httpProbe['status'] . ' → ' . $loc[0],
                $perm ? 'Plain HTTP requests are permanently redirected to HTTPS.'
                    : 'HTTP redirects to HTTPS, but with a temporary (' . $httpProbe['status'] . ') redirect. Use 301 or 308 so browsers and search engines remember it.');
        } else {
            $r->add($cat, 'http_redirect', 'HTTP redirects to HTTPS', 'fail', 'medium',
                'HTTP ' . $httpProbe['status'] . ($loc ? ' → ' . $loc[0] : ''),
                'The site still answers over plain HTTP without sending visitors to HTTPS, so anyone typing the address can be intercepted.',
                "# Apache (.htaccess)\nRewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n\n# nginx\nserver { listen 80; server_name example.com; return 301 https://\$host\$request_uri; }");
        }
    }

    $hsts = hp_hget($h, 'strict-transport-security');
    $hstsRec = 'max-age=31536000; includeSubDomains';
    if (!$https) {
        $r->add($cat, 'hsts', 'Strict-Transport-Security (HSTS)', 'info', 'medium', $hsts ? $hsts[0] : '(missing)',
            'HSTS only works on HTTPS pages. Enable HTTPS first.');
    } elseif (!$hsts) {
        $r->add($cat, 'hsts', 'Strict-Transport-Security (HSTS)', 'fail', 'medium', '(missing)',
            'Without HSTS, a visitor\'s first request can go over plain HTTP, giving an attacker on the network a chance to downgrade the connection (SSL stripping).',
            'Strict-Transport-Security: ' . $hstsRec);
        $r->rec('Strict-Transport-Security', $hstsRec);
    } else {
        $v = $hsts[0];
        $age = preg_match('/max-age\s*=\s*"?(\d+)/i', $v, $m) ? (int)$m[1] : 0;
        if ($age < 15552000) {
            $r->add($cat, 'hsts', 'Strict-Transport-Security (HSTS)', 'warn', 'medium', $v,
                'HSTS is set but max-age is ' . ($age ? 'only ' . round($age / 86400) . ' days' : 'missing or 0') . '. Use at least 6 months (one year is standard) once HTTPS works everywhere.',
                'Strict-Transport-Security: ' . $hstsRec);
            $r->rec('Strict-Transport-Security', $hstsRec);
        } elseif (stripos($v, 'includesubdomains') === false) {
            $r->add($cat, 'hsts', 'Strict-Transport-Security (HSTS)', 'pass', 'medium', $v,
                'HSTS is active. Consider adding includeSubDomains once every subdomain supports HTTPS.');
        } else {
            $r->add($cat, 'hsts', 'Strict-Transport-Security (HSTS)', 'pass', 'medium', $v,
                'Browsers will only use HTTPS for this site and its subdomains'
                . (stripos($v, 'preload') !== false ? ', and it is ready for the browser preload list (hstspreload.org).' : '.'));
        }
    }

    // ---- Content Security Policy -------------------------------------------
    hp_check_csp($r, $h);

    // ---- Browser protections -------------------------------------------------
    $cat = 'Browser protections';
    $csp = hp_hget($h, 'content-security-policy');
    $fa = false;
    foreach ($csp as $c) {
        if (preg_match('/(^|;)\s*frame-ancestors\s/i', $c)) {
            $fa = true;
        }
    }
    $xfo = hp_hget($h, 'x-frame-options');
    if ($fa) {
        $r->add($cat, 'framing', 'Clickjacking protection', 'pass', 'medium', 'CSP frame-ancestors' . ($xfo ? ' + X-Frame-Options: ' . $xfo[0] : ''),
            'Other sites cannot embed this page in a frame.');
    } elseif ($xfo && preg_match('/^\s*(deny|sameorigin)\s*$/i', $xfo[0])) {
        $r->add($cat, 'framing', 'Clickjacking protection', 'pass', 'medium', $xfo[0], 'Other sites cannot embed this page in a frame.');
    } elseif ($xfo) {
        $r->add($cat, 'framing', 'Clickjacking protection', 'warn', 'medium', $xfo[0],
            'X-Frame-Options has a value modern browsers ignore (ALLOW-FROM is not supported). Use DENY or SAMEORIGIN, or CSP frame-ancestors.',
            'X-Frame-Options: SAMEORIGIN');
        $r->rec('X-Frame-Options', 'SAMEORIGIN');
    } else {
        $r->add($cat, 'framing', 'Clickjacking protection', 'fail', 'medium', '(missing)',
            'Any site can load this page in an invisible frame and trick visitors into clicking buttons they cannot see (clickjacking).',
            "X-Frame-Options: SAMEORIGIN\n# modern alternative, inside your CSP:  frame-ancestors 'self'");
        $r->rec('X-Frame-Options', 'SAMEORIGIN');
    }

    $xcto = hp_hget($h, 'x-content-type-options');
    if ($xcto && stripos($xcto[0], 'nosniff') !== false) {
        $r->add($cat, 'xcto', 'X-Content-Type-Options', 'pass', 'low', $xcto[0], 'Browsers will not guess (sniff) content types.');
    } else {
        $r->add($cat, 'xcto', 'X-Content-Type-Options', 'fail', 'low', $xcto ? $xcto[0] : '(missing)',
            'Browsers may treat files as a different type than intended, for example running an uploaded "image" as a script.',
            'X-Content-Type-Options: nosniff');
        $r->rec('X-Content-Type-Options', 'nosniff');
    }

    $rp = hp_hget($h, 'referrer-policy');
    $rpVal = '';
    if ($rp) {
        foreach (array_reverse(array_map('trim', explode(',', end($rp)))) as $tok) {
            if ($tok !== '') {
                $rpVal = strtolower($tok);
                break;
            }
        }
    }
    if ($rpVal === '') {
        $r->add($cat, 'referrer', 'Referrer-Policy', 'warn', 'low', '(missing)',
            'Modern browsers default to a safe policy, but older ones send the full URL (which can contain tokens or private IDs) to every site you link to.',
            'Referrer-Policy: strict-origin-when-cross-origin');
        $r->rec('Referrer-Policy', 'strict-origin-when-cross-origin');
    } elseif (in_array($rpVal, array('unsafe-url', 'no-referrer-when-downgrade'), true)) {
        $r->add($cat, 'referrer', 'Referrer-Policy', 'warn', 'low', end($rp),
            '"' . $rpVal . '" sends full URLs, including paths and query strings, to other sites.',
            'Referrer-Policy: strict-origin-when-cross-origin');
        $r->rec('Referrer-Policy', 'strict-origin-when-cross-origin');
    } else {
        $r->add($cat, 'referrer', 'Referrer-Policy', 'pass', 'low', end($rp), 'Full URLs are not leaked to other sites.');
    }

    $pp = hp_hget($h, 'permissions-policy');
    if ($pp) {
        $r->add($cat, 'permissions', 'Permissions-Policy', 'pass', 'low', $pp[0], 'Powerful browser features are restricted.');
    } else {
        $r->add($cat, 'permissions', 'Permissions-Policy', 'info', 'low', '(missing)',
            'Optional hardening: switch off browser features this site never uses, so injected or third-party scripts cannot use them either.',
            'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()');
        $r->rec('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
    }

    $coop = hp_hget($h, 'cross-origin-opener-policy');
    if ($coop && preg_match('/same-origin/i', $coop[0])) {
        $r->add($cat, 'coop', 'Cross-Origin-Opener-Policy', 'pass', 'low', $coop[0], 'Pages from other sites cannot keep a handle on this window.');
    } else {
        $r->add($cat, 'coop', 'Cross-Origin-Opener-Policy', 'info', 'low', $coop ? $coop[0] : '(missing)',
            'Optional hardening: isolates this page from windows opened by or opening other sites, blocking cross-window attacks like tabnabbing and some XS-Leaks. Test it first if you use OAuth or payment popups.',
            'Cross-Origin-Opener-Policy: same-origin');
    }

    // ---- CORS ----------------------------------------------------------------
    $cat = 'Cross-origin access (CORS)';
    $acao = hp_hget($h, 'access-control-allow-origin');
    $acac = hp_hget($h, 'access-control-allow-credentials');
    $creds = $acac && strtolower(trim($acac[0])) === 'true';
    if (!$acao) {
        $r->add($cat, 'cors', 'CORS is not overly permissive', 'pass', 'high', 'no Access-Control-Allow-Origin',
            'Other websites cannot read this page\'s responses from a visitor\'s browser.');
    } else {
        $v = trim($acao[0]);
        if (strcasecmp($v, HEADPATROL_PROBE_ORIGIN) === 0) {
            if ($creds) {
                $r->add($cat, 'cors', 'CORS is not overly permissive', 'fail', 'high', 'reflects any origin + credentials',
                    'The server copied HeadPatrol\'s made-up Origin into Access-Control-Allow-Origin and allows credentials. Any website can make logged-in requests on a visitor\'s behalf and read the responses, including private data.',
                    'Only allow a fixed list of trusted origins. Never reflect the Origin header back unchecked.');
            } else {
                $r->add($cat, 'cors', 'CORS is not overly permissive', 'warn', 'medium', 'reflects any origin',
                    'The server echoes back any Origin it is sent. That is fine for truly public data, but risky if responses ever depend on cookies or IP-based access.',
                    'Check origins against an allow-list instead of reflecting them.');
            }
        } elseif (strtolower($v) === 'null') {
            $r->add($cat, 'cors', 'CORS is not overly permissive', 'warn', 'medium', 'null',
                'Access-Control-Allow-Origin: null can be triggered by sandboxed iframes on any site.', 'Remove "null" from the allowed origins.');
        } elseif ($v === '*') {
            $r->add($cat, 'cors', 'CORS is not overly permissive', 'info', 'low', '*',
                'Any website can read this response (without cookies). That is normal for public APIs and assets, but should not be used on pages with private content.');
        } else {
            $r->add($cat, 'cors', 'CORS is not overly permissive', 'pass', 'high', $v, 'Cross-origin reads are limited to a specific origin.');
        }
    }

    // ---- Cookies ---------------------------------------------------------------
    $cookies = hp_hget($h, 'set-cookie');
    $cat = 'Cookies';
    foreach (array_slice($cookies, 0, 25) as $i => $raw) {
        hp_check_cookie($r, $raw, $https, $i);
    }
    if (count($cookies) > 25) {
        $r->add($cat, 'cookies_more', 'More cookies', 'info', 'low', count($cookies) . ' cookies', 'Only the first 25 cookies were analysed.');
    }

    // ---- Information disclosure ------------------------------------------------
    $cat = 'Information disclosure';
    $leaks = array();
    $srv = hp_hget($h, 'server');
    if ($srv && preg_match('/\d/', $srv[0])) {
        $leaks[] = 'Server: ' . $srv[0];
    }
    foreach (array('x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator', 'x-runtime', 'x-version') as $n) {
        foreach (hp_hget($h, $n) as $v) {
            $leaks[] = $n . ': ' . $v;
        }
    }
    if ($leaks) {
        $r->add($cat, 'version_leak', 'No software versions disclosed', 'warn', 'low', implode("\n", $leaks),
            'These headers announce what software (and often which exact version) runs the site, so attackers can look up matching exploits instantly.',
            "# Apache\nServerTokens Prod\nServerSignature Off\nHeader unset X-Powered-By\n\n# nginx\nserver_tokens off;\nfastcgi_hide_header X-Powered-By;\n\n# php.ini\nexpose_php = Off");
    } else {
        $r->add($cat, 'version_leak', 'No software versions disclosed', 'pass', 'low', 'none', 'No software versions are advertised in the headers.');
    }

    // ---- Deprecated headers ------------------------------------------------------
    $cat = 'Deprecated headers';
    $xxss = hp_hget($h, 'x-xss-protection');
    if ($xxss && trim($xxss[0]) !== '0') {
        $r->add($cat, 'x_xss', 'X-XSS-Protection is not enabled', 'info', 'low', $xxss[0],
            'The browser XSS filter this controls has been removed from all modern browsers, and in older ones it could be abused to leak data. Set it to 0 or remove it, and rely on CSP.',
            'X-XSS-Protection: 0');
    }
    if (hp_hget($h, 'public-key-pins')) {
        $r->add($cat, 'hpkp', 'No HTTP Public Key Pinning', 'warn', 'medium', 'Public-Key-Pins present',
            'HPKP is obsolete and was removed from browsers because a mistake could lock visitors out of the site for months.', 'Remove the Public-Key-Pins header.');
    }
    if (hp_hget($h, 'expect-ct')) {
        $r->add($cat, 'expect_ct', 'No Expect-CT header', 'info', 'low', 'Expect-CT present',
            'Expect-CT is obsolete: Certificate Transparency is now enforced by default. You can remove it.');
    }

    return $r;
}

function hp_check_csp($r, $h)
{
    $cat = 'Content Security Policy';
    $enf = hp_hget($h, 'content-security-policy');
    $ro = hp_hget($h, 'content-security-policy-report-only');
    $starter = "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'; upgrade-insecure-requests";

    if (!$enf) {
        if ($ro) {
            $r->add($cat, 'csp', 'Content-Security-Policy is enforced', 'warn', 'medium', 'Report-Only: ' . $ro[0],
                'A CSP exists in Report-Only mode: violations are reported but nothing is blocked. Once the reports are clean, switch the header name to Content-Security-Policy.');
        } else {
            $r->add($cat, 'csp', 'Content-Security-Policy is enforced', 'fail', 'medium', '(missing)',
                'Without a CSP, any cross-site scripting (XSS) bug lets an attacker run their own JavaScript on this site. A CSP is the strongest browser-side defence. Start with the policy below in Content-Security-Policy-Report-Only mode, fix what it reports, then enforce it.',
                'Content-Security-Policy: ' . $starter);
            $r->rec('Content-Security-Policy', $starter);
        }
        return;
    }

    $policy = $enf[0];
    $d = hp_parse_csp($policy);
    $r->add($cat, 'csp', 'Content-Security-Policy is enforced', 'pass', 'medium', $policy,
        count($enf) > 1 ? 'A CSP is enforced (' . count($enf) . ' policies are sent; browsers apply all of them, and the analysis below covers the first).' : 'A CSP is enforced.');

    $script = isset($d['script-src']) ? $d['script-src'] : (isset($d['default-src']) ? $d['default-src'] : null);
    $from = isset($d['script-src']) ? 'script-src' : 'default-src';
    if ($script === null) {
        $r->add($cat, 'csp_scripts', 'CSP restricts scripts', 'fail', 'medium', 'no script-src or default-src',
            'The policy never restricts where scripts can load from, so it gives no protection against XSS.',
            "Add: default-src 'self'   (or a specific script-src)");
    } else {
        $lower = array_map('strtolower', $script);
        $hasNonceHash = (bool)preg_grep("/^'(nonce-|sha256-|sha384-|sha512-)/", $lower);
        $strictDynamic = in_array("'strict-dynamic'", $lower, true);
        $issues = array();
        if (in_array("'unsafe-inline'", $lower, true) && !$hasNonceHash) {
            $issues[] = array('fail', 'medium', "'unsafe-inline' allows inline scripts, which is exactly what most XSS payloads are. Use nonces or hashes instead.");
        }
        if (!$strictDynamic) {
            $wild = array_values(array_intersect($lower, array('*', 'http:', 'https:', 'data:', 'blob:')));
            if ($wild) {
                $issues[] = array('fail', 'medium', 'Scripts may load from ' . implode(', ', $wild) . ', which means almost anywhere. An attacker can host their script on any site.');
            }
            $plain = preg_grep('#^http://#', $lower);
            if ($plain) {
                $issues[] = array('warn', 'low', 'Scripts are allowed over plain HTTP (' . implode(', ', $plain) . '), where they can be tampered with in transit.');
            }
        }
        if ($issues) {
            $worst = 'warn';
            $sev = 'low';
            $text = array();
            foreach ($issues as $is) {
                if ($is[0] === 'fail') {
                    $worst = 'fail';
                    $sev = 'medium';
                }
                $text[] = $is[2];
            }
            $r->add($cat, 'csp_scripts', 'CSP restricts scripts', $worst, $sev, $from . ' ' . implode(' ', $script), implode(' ', $text),
                "script-src 'self' 'nonce-{random-per-request}' 'strict-dynamic'");
        } else {
            $r->add($cat, 'csp_scripts', 'CSP restricts scripts', 'pass', 'medium', $from . ' ' . implode(' ', $script),
                $hasNonceHash ? 'Scripts are locked down with nonces or hashes. Excellent.' : 'Scripts can only load from listed sources.');
        }
        if (in_array("'unsafe-eval'", $lower, true)) {
            $r->add($cat, 'csp_eval', 'CSP blocks eval()', 'warn', 'low', "'unsafe-eval'",
                "'unsafe-eval' lets scripts turn strings into code (eval, new Function), which widens the impact of injection bugs. Some older libraries need it.");
        }
    }

    $object = isset($d['object-src']) ? $d['object-src'] : (isset($d['default-src']) ? $d['default-src'] : null);
    if ($object === null || array_map('strtolower', $object) !== array("'none'")) {
        $r->add($cat, 'csp_object', "CSP sets object-src 'none'", 'warn', 'low', $object === null ? '(not set)' : implode(' ', $object),
            'Plugins (<object>, <embed>) are a classic way around a CSP. Almost no site needs them.', "object-src 'none'");
    } else {
        $r->add($cat, 'csp_object', "CSP sets object-src 'none'", 'pass', 'low', "'none'", 'Plugin content is blocked.');
    }

    if (!isset($d['base-uri'])) {
        $r->add($cat, 'csp_base', 'CSP restricts base-uri', 'warn', 'low', '(not set)',
            'An injected <base> tag can redirect every relative script URL to an attacker\'s server, even with a strict script-src.', "base-uri 'self'");
    } else {
        $r->add($cat, 'csp_base', 'CSP restricts base-uri', 'pass', 'low', implode(' ', $d['base-uri']), 'Injected <base> tags cannot hijack relative URLs.');
    }
}

function hp_check_cookie($r, $raw, $https, $i)
{
    $parts = array_map('trim', explode(';', $raw));
    $nv = explode('=', array_shift($parts), 2);
    $name = trim($nv[0]);
    $attrs = array();
    foreach ($parts as $p) {
        $kv = explode('=', $p, 2);
        $attrs[strtolower(trim($kv[0]))] = isset($kv[1]) ? trim($kv[1]) : true;
    }
    $sensitive = (bool)preg_match('/sess|sid|auth|token|login|jwt|remember|csrf|xsrf|user|account/i', $name);
    $secure = isset($attrs['secure']);
    $httpOnly = isset($attrs['httponly']);
    $ss = isset($attrs['samesite']) && is_string($attrs['samesite']) ? strtolower($attrs['samesite']) : '';

    $issues = array();
    $status = 'pass';
    $sev = 'low';
    $bump = function ($s, $v) use (&$status, &$sev) {
        $rank = array('pass' => 0, 'info' => 1, 'warn' => 2, 'fail' => 3);
        $srank = array('low' => 0, 'medium' => 1, 'high' => 2);
        if ($rank[$s] > $rank[$status] || ($rank[$s] === $rank[$status] && $srank[$v] > $srank[$sev])) {
            $status = $s;
            $sev = $v;
        }
    };
    if ($https && !$secure) {
        $issues[] = 'Missing Secure: the cookie can be sent over plain HTTP and intercepted.';
        $bump('fail', $sensitive ? 'medium' : 'low');
    }
    if (!$httpOnly) {
        if ($sensitive) {
            $issues[] = 'Missing HttpOnly: JavaScript (including XSS payloads) can read this cookie, and its name suggests it is sensitive.';
            $bump('fail', 'medium');
        } else {
            $issues[] = 'No HttpOnly: fine only if your own JavaScript needs to read it.';
            $bump('info', 'low');
        }
    }
    if ($ss === 'none' && !$secure) {
        $issues[] = 'SameSite=None without Secure: browsers will reject this cookie.';
        $bump('fail', 'low');
    } elseif ($ss === '') {
        $issues[] = 'No SameSite attribute: browsers pick a default, which differs between them. Set Lax or Strict explicitly to blunt CSRF.';
        $bump('warn', 'low');
    }

    $flags = array();
    foreach (array('secure' => 'Secure', 'httponly' => 'HttpOnly') as $k => $label) {
        if (isset($attrs[$k])) {
            $flags[] = $label;
        }
    }
    if ($ss !== '') {
        $flags[] = 'SameSite=' . ucfirst($ss);
    }
    $prefix = (stripos($name, '__Host-') === 0 || stripos($name, '__Secure-') === 0) ? ' Uses a secure name prefix.' : '';

    $r->add('Cookies', 'cookie_' . $i, 'Cookie "' . hp_clean($name, 80) . '"', $status, $sev,
        $flags ? implode('; ', $flags) : 'no security flags',
        $issues ? implode(' ', $issues) . $prefix : 'All security flags are set.' . $prefix,
        $issues ? 'Set-Cookie: ' . hp_clean($name, 80) . '=…; Path=/; Secure; HttpOnly; SameSite=Lax' : '');
}

// ----------------------------------------------------------------------------
//  Config snippets
// ----------------------------------------------------------------------------

function hp_config_snippets($rec)
{
    if (!$rec) {
        return array();
    }
    $apache = "# Apache: .htaccess or <VirtualHost> (needs mod_headers)\n<IfModule mod_headers.c>\n";
    $nginx = "# nginx: inside your server { } block\n";
    $php = "<?php\n// PHP: run before any output, e.g. at the top of a shared bootstrap file\n";
    $iis = "<!-- IIS: web.config -->\n<configuration>\n  <system.webServer>\n    <httpProtocol>\n      <customHeaders>\n";
    $netlify = "# Netlify / Cloudflare Pages: a file named _headers in your publish folder\n/*\n";
    foreach ($rec as $n => $v) {
        $apache .= '    Header always set ' . $n . ' "' . str_replace('"', '\\"', $v) . "\"\n";
        $nginx .= 'add_header ' . $n . ' "' . str_replace('"', '\\"', $v) . "\" always;\n";
        $php .= 'header(' . var_export($n . ': ' . $v, true) . ");\n";
        $iis .= '        <add name="' . hp_h($n) . '" value="' . hp_h($v) . "\" />\n";
        $netlify .= '  ' . $n . ': ' . $v . "\n";
    }
    $apache .= "</IfModule>\n";
    $iis .= "      </customHeaders>\n    </httpProtocol>\n  </system.webServer>\n</configuration>\n";
    return array('Apache' => $apache, 'nginx' => $nginx, 'PHP' => $php, 'IIS' => $iis, 'Netlify / CF Pages' => $netlify);
}

// ----------------------------------------------------------------------------
//  Rate limiting (web mode)
// ----------------------------------------------------------------------------

function hp_client_ip()
{
    $hdr = HEADPATROL_CLIENT_IP_HEADER;
    if ($hdr !== '' && !empty($_SERVER[$hdr])) {
        $first = trim(explode(',', (string)$_SERVER[$hdr])[0]);
        if (filter_var($first, FILTER_VALIDATE_IP)) {
            return $first;
        }
    }
    return isset($_SERVER['REMOTE_ADDR']) ? (string)$_SERVER['REMOTE_ADDR'] : '0.0.0.0';
}

/** Sliding one-minute window, stored in the system temp dir. Returns seconds to wait, or 0 if allowed. */
function hp_rate_limit($ip)
{
    $dir = rtrim(sys_get_temp_dir(), '/\\') . DIRECTORY_SEPARATOR . 'headpatrol-rl-' . substr(hash('sha256', __FILE__), 0, 12);
    if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
        return 0; // cannot store state; fail open rather than break the tool
    }
    $now = time();
    if (mt_rand(1, 100) === 1) {
        foreach ((array)@glob($dir . '/*.json') as $f) {
            if (@filemtime($f) < $now - 3600) {
                @unlink($f);
            }
        }
    }
    $buckets = array(
        array('ip-' . hash('sha256', $ip . '|' . __FILE__), HEADPATROL_RATE_LIMIT_PER_IP),
        array('global', HEADPATROL_RATE_LIMIT_GLOBAL),
    );
    foreach ($buckets as $b) {
        $fh = @fopen($dir . DIRECTORY_SEPARATOR . $b[0] . '.json', 'c+');
        if (!$fh) {
            continue;
        }
        flock($fh, LOCK_EX);
        $hits = json_decode((string)stream_get_contents($fh), true);
        $hits = array_values(array_filter(is_array($hits) ? $hits : array(), function ($t) use ($now) {
            return is_int($t) && $t > $now - 60;
        }));
        if (count($hits) >= $b[1]) {
            flock($fh, LOCK_UN);
            fclose($fh);
            return max(1, 60 - ($now - min($hits)));
        }
        $hits[] = $now;
        ftruncate($fh, 0);
        rewind($fh);
        fwrite($fh, json_encode($hits));
        fflush($fh);
        flock($fh, LOCK_UN);
        fclose($fh);
    }
    return 0;
}

// ----------------------------------------------------------------------------
//  Web mode
// ----------------------------------------------------------------------------

function hp_web_main()
{
    @set_time_limit(60);
    $nonce = base64_encode(random_bytes(16));
    $input = isset($_GET['url']) && is_string($_GET['url']) ? $_GET['url'] : '';
    $json = isset($_GET['format']) && $_GET['format'] === 'json';

    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    header('Cache-Control: no-store');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
    if (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off') {
        header('Strict-Transport-Security: max-age=31536000');
    }

    $result = null;
    $retry = 0;
    if ($input !== '') {
        $retry = hp_rate_limit(hp_client_ip());
        if ($retry > 0) {
            http_response_code(429);
            header('Retry-After: ' . $retry);
            $result = array('error' => 'Too many scans. Please wait ' . $retry . ' seconds and try again.');
        } else {
            $result = hp_scan($input, array('allow_private' => HEADPATROL_ALLOW_PRIVATE_TARGETS));
            if (isset($result['error']) && $json) {
                http_response_code(422);
            }
        }
    }

    if ($json) {
        header('Content-Type: application/json; charset=utf-8');
        header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'");
        if ($result === null) {
            http_response_code(400);
            $result = array('error' => 'Pass the site to scan as ?url=https://example.com&format=json');
        }
        if (isset($result['chain'])) {
            unset($result['chain']);
        }
        echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        return;
    }

    header('Content-Type: text/html; charset=UTF-8');
    header("Content-Security-Policy: default-src 'none'; style-src 'nonce-$nonce'; script-src 'nonce-$nonce'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    header('X-Frame-Options: DENY');
    if ($input !== '') {
        header('X-Robots-Tag: noindex');
    }
    hp_render_page($nonce, $input, $result);
}

function hp_render_page($nonce, $input, $result)
{
    $labels = array('pass' => 'Pass', 'warn' => 'Warning', 'fail' => 'Fail', 'info' => 'Info');
    $ok = is_array($result) && !isset($result['error']);
    $self = strtok(isset($_SERVER['REQUEST_URI']) ? (string)$_SERVER['REQUEST_URI'] : '', '?');
    ?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= $ok ? 'HeadPatrol: ' . hp_h(parse_url($result['final_url'], PHP_URL_HOST)) . ' (' . hp_h($result['grade']) . ')' : 'HeadPatrol: security headers scanner' ?></title>
<meta name="description" content="Free security headers scanner. Grades HSTS, CSP, cookies, CORS and more, and gives you ready-to-paste fixes.">
<style nonce="<?= hp_h($nonce) ?>"><?= hp_css() ?></style>
</head>
<body>
<header class="top">
  <div class="wrap">
    <a class="brand" href="<?= hp_h($self) ?>"><span class="logo" aria-hidden="true">◆</span> HeadPatrol</a>
    <p class="tag">Patrol any site's security headers. One file. No install. Real fixes.</p>
    <form method="get" class="scan" role="search">
      <label for="url" class="sr">Website to scan</label>
      <input id="url" name="url" type="text" inputmode="url" autocomplete="url" spellcheck="false" placeholder="example.com" value="<?= hp_h($input) ?>" required maxlength="2048"<?= $input === '' ? ' autofocus' : '' ?>>
      <button type="submit">Scan</button>
    </form>
  </div>
</header>
<main class="wrap">
<?php if ($result === null): ?>
  <section class="intro">
    <div class="feat"><h2>Deep CSP analysis</h2><p>Not just "is there a CSP": finds <code>'unsafe-inline'</code>, wildcards, missing <code>object-src</code> and <code>base-uri</code>.</p></div>
    <div class="feat"><h2>Cookies &amp; CORS</h2><p>Checks every cookie's <code>Secure</code>, <code>HttpOnly</code> and <code>SameSite</code>, and detects CORS that reflects any origin.</p></div>
    <div class="feat"><h2>Copy-paste fixes</h2><p>Generates the missing headers for Apache, nginx, PHP, IIS and Netlify / Cloudflare Pages.</p></div>
  </section>
  <p class="muted center">Only public websites can be scanned. Only the response headers are read; page content is never downloaded or stored.</p>
<?php elseif (!$ok): ?>
  <div class="error" role="alert"><strong>Scan not completed.</strong> <?= hp_h($result['error']) ?></div>
<?php else:
    $host = parse_url($result['final_url'], PHP_URL_HOST);
    $share = $self . '?url=' . rawurlencode($result['input']);
    $snips = hp_config_snippets($result['recommended_headers']);
    $groups = array();
    $order = array('fail' => 0, 'warn' => 1, 'info' => 2, 'pass' => 3);
    $sevOrder = array('high' => 0, 'medium' => 1, 'low' => 2);
    foreach ($result['results'] as $n => $it) {
        $it['_n'] = $n;
        $groups[$it['category']][] = $it;
    }
    foreach ($groups as $k => $list) {
        usort($list, function ($a, $b) use ($order, $sevOrder) {
            $d = $order[$a['status']] - $order[$b['status']];
            if ($d) return $d;
            $d = $sevOrder[$a['severity']] - $sevOrder[$b['severity']];
            return $d ? $d : $a['_n'] - $b['_n'];
        });
        $groups[$k] = $list;
    }
    $gclass = 'g-' . str_replace('+', 'p', $result['grade']);
?>
  <section class="summary">
    <div class="grade <?= hp_h($gclass) ?>"><?= hp_h($result['grade']) ?></div>
    <div class="sum-main">
      <h1><?= hp_h($host) ?></h1>
      <div class="meta">
        <span><b><?= (int)$result['score'] ?></b>/100</span>
        <span class="c-fail"><b><?= (int)$result['counts']['fail'] ?></b> failed</span>
        <span class="c-warn"><b><?= (int)$result['counts']['warn'] ?></b> warnings</span>
        <span class="c-pass"><b><?= (int)$result['counts']['pass'] ?></b> passed</span>
      </div>
      <dl class="facts">
        <dt>Final URL</dt><dd><code><?= hp_h($result['final_url']) ?></code></dd>
        <dt>Response</dt><dd>HTTP <?= hp_h($result['http_version']) ?> <?= (int)$result['status'] ?> · <?= (int)$result['time_ms'] ?> ms<?= $result['ip'] !== '' ? ' · ' . hp_h($result['ip']) : '' ?></dd>
        <dt>Scanned</dt><dd><?= hp_h($result['scanned_at']) ?></dd>
      </dl>
    </div>
    <div class="actions">
      <button type="button" class="ghost" data-copy="<?= hp_h($share) ?>" data-absolute="1">Copy share link</button>
      <a class="ghost btn" href="<?= hp_h($share . '&format=json') ?>">JSON</a>
    </div>
  </section>

  <?php if ($result['notice'] !== ''): ?>
  <div class="notice" role="status"><?= hp_h($result['notice']) ?></div>
  <?php endif; ?>

  <?php if (count($result['redirects']) > 1): ?>
  <section>
    <h2>Redirect chain</h2>
    <ol class="chain">
      <?php foreach ($result['redirects'] as $c): ?>
      <li><span class="code"><?= (int)$c['status'] ?></span> <code><?= hp_h($c['url']) ?></code></li>
      <?php endforeach; ?>
    </ol>
  </section>
  <?php endif; ?>

  <div class="toolbar"><label><input type="checkbox" id="hide-pass"> Hide passed checks</label></div>

  <?php foreach ($groups as $cat => $items): ?>
  <section>
    <h2><?= hp_h($cat) ?></h2>
    <?php foreach ($items as $i): ?>
    <article class="item s-<?= hp_h($i['status']) ?>">
      <div class="head">
        <span class="pill p-<?= hp_h($i['status']) ?>"><?= hp_h($labels[$i['status']]) ?></span>
        <h3><?= hp_h($i['title']) ?></h3>
        <?php if ($i['status'] === 'fail' || $i['status'] === 'warn'): ?><span class="sev sev-<?= hp_h($i['severity']) ?>"><?= hp_h($i['severity']) ?></span><?php endif; ?>
      </div>
      <div class="body">
        <div class="cur"><code><?= nl2br(hp_h($i['current'])) ?></code></div>
        <p><?= hp_h($i['detail']) ?></p>
        <?php if ($i['snippet'] !== '' && $i['status'] !== 'pass'): ?><pre><?= hp_h($i['snippet']) ?></pre><?php endif; ?>
      </div>
    </article>
    <?php endforeach; ?>
  </section>
  <?php endforeach; ?>

  <?php if ($snips): ?>
  <section class="fixes">
    <h2>Fix it: copy-paste configuration</h2>
    <p class="muted">The missing or weak headers above, ready for your server. Test on a staging site first, and roll out a new Content-Security-Policy as <code>Content-Security-Policy-Report-Only</code> before enforcing it.</p>
    <div class="tabs" role="tablist">
      <?php $first = true; foreach ($snips as $name => $code): $id = 'tab-' . preg_replace('/[^a-z]/', '', strtolower($name)); ?>
      <button type="button" role="tab" class="tab<?= $first ? ' on' : '' ?>" aria-selected="<?= $first ? 'true' : 'false' ?>" data-tab="<?= hp_h($id) ?>"><?= hp_h($name) ?></button>
      <?php $first = false; endforeach; ?>
    </div>
    <?php $first = true; foreach ($snips as $name => $code): $id = 'tab-' . preg_replace('/[^a-z]/', '', strtolower($name)); ?>
    <div class="panel<?= $first ? ' on' : '' ?>" id="<?= hp_h($id) ?>" role="tabpanel">
      <button type="button" class="copy" data-copy-target="<?= hp_h($id) ?>-code">Copy</button>
      <pre id="<?= hp_h($id) ?>-code"><?= hp_h($code) ?></pre>
    </div>
    <?php $first = false; endforeach; ?>
  </section>
  <?php endif; ?>

  <section>
    <details class="raw">
      <summary>Raw response headers (<?= count($result['headers']) ?>)</summary>
      <table>
        <?php foreach ($result['headers'] as $hd): ?>
        <tr><th><?= hp_h($hd[0]) ?></th><td><?= strcasecmp($hd[0], 'set-cookie') === 0 ? hp_h(preg_replace('/=[^;]*/', '=…', $hd[1], 1)) : hp_h($hd[1]) ?></td></tr>
        <?php endforeach; ?>
      </table>
    </details>
  </section>
<?php endif; ?>
  <footer>
    <a href="<?= hp_h(HEADPATROL_URL) ?>">HeadPatrol</a> v<?= hp_h(HEADPATROL_VERSION) ?> · free and open source (MIT) ·
    checking your own PHP server? Try <a href="https://github.com/kettalevi/PHPatrol">PHPatrol</a>.
    <br>Results describe the headers on the scanned page only. A good grade covers the basics; it does not prove a site is free of vulnerabilities.
  </footer>
</main>
<script nonce="<?= hp_h($nonce) ?>"><?= hp_js() ?></script>
</body>
</html>
<?php
}

function hp_css()
{
    return <<<'CSS'
:root{--bg:#f5f6f8;--card:#fff;--ink:#14161b;--muted:#5b6270;--line:#e2e5ea;--code:#eef0f4;
--pass:#1d8348;--pass-bg:#e3f4ea;--warn:#946000;--warn-bg:#fcf0d9;--fail:#c0392b;--fail-bg:#fbe6e4;--info:#2a5fb4;--info-bg:#e5edfa;
--accent:#0f766e;--accent-ink:#fff;--top:#0b1f1d;--top-ink:#eef6f5}
@media (prefers-color-scheme:dark){:root{--bg:#0d0f12;--card:#16191e;--ink:#e6e8ec;--muted:#98a0ad;--line:#272b33;--code:#20242b;
--pass:#4ccb82;--pass-bg:#15301f;--warn:#f0b54a;--warn-bg:#352a12;--fail:#ff6f61;--fail-bg:#3a1a17;--info:#7aa7ff;--info-bg:#17243b;--accent:#2dd4bf;--accent-ink:#04201d;--top:#06100f}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Ubuntu,sans-serif}
a{color:var(--accent)}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
code{background:var(--code);padding:1px 6px;border-radius:4px;word-break:break-word}
pre{background:var(--code);padding:12px 14px;border-radius:6px;overflow-x:auto;margin:8px 0 0;white-space:pre}
.wrap{max-width:960px;margin:0 auto;padding:0 16px}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
.top{background:var(--top);color:var(--top-ink);padding:28px 0 30px}
.brand{color:var(--top-ink);text-decoration:none;font-weight:800;font-size:22px;letter-spacing:-.01em}
.logo{color:#2dd4bf}
.tag{margin:4px 0 18px;color:#a9c2bf}
.scan{display:flex;gap:8px}
.scan input{flex:1;min-width:0;font:inherit;font-size:16px;padding:12px 14px;border-radius:8px;border:1px solid #2c4a46;background:#0f2a27;color:#fff}
.scan input::placeholder{color:#7f9a97}
.scan input:focus{outline:2px solid #2dd4bf;outline-offset:1px}
button,.btn{font:inherit;cursor:pointer;border-radius:8px;border:1px solid transparent;padding:10px 18px;background:var(--accent);color:var(--accent-ink);font-weight:600;text-decoration:none;display:inline-block}
.scan button{background:#2dd4bf;color:#04201d;font-size:16px}
button.ghost,.btn.ghost{background:transparent;color:var(--ink);border-color:var(--line);font-weight:500;padding:7px 12px;font-size:14px}
.intro{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;margin:28px 0 16px}
.feat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
.feat h2{font-size:16px;margin:0 0 6px}.feat p{margin:0;color:var(--muted);font-size:14px}
.center{text-align:center}.muted{color:var(--muted);font-size:14px}
.notice{margin:12px 0;padding:12px 14px;border-radius:8px;background:var(--warn-bg);border:1px solid var(--warn);font-size:14px}
.error{margin:28px 0;padding:14px 16px;border-radius:8px;background:var(--fail-bg);border:1px solid var(--fail);color:var(--ink)}
.summary{display:flex;gap:18px;align-items:flex-start;flex-wrap:wrap;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px;margin:24px 0 8px}
.grade{width:84px;height:84px;border-radius:16px;display:grid;place-items:center;font-size:38px;font-weight:800;color:#fff;flex:none}
.g-Ap{background:#0e7a42}.g-A{background:#1d8348}.g-B{background:#5a9a2a}.g-C{background:#b8860b}.g-D{background:#d0641c}.g-F{background:#c0392b}
.sum-main{flex:1;min-width:220px}
.sum-main h1{margin:0;font-size:24px;word-break:break-all}
.meta{display:flex;gap:14px;flex-wrap:wrap;margin:4px 0 10px;font-size:14px}
.c-fail b{color:var(--fail)}.c-warn b{color:var(--warn)}.c-pass b{color:var(--pass)}
.facts{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;margin:0;font-size:14px}
.facts dt{color:var(--muted)}.facts dd{margin:0;min-width:0;word-break:break-all}
.actions{display:flex;gap:8px;flex-wrap:wrap}
.toolbar{margin:16px 0 0;font-size:14px}
section h2{font-size:17px;margin:26px 0 10px}
.chain{margin:0;padding-left:22px}.chain li{margin:4px 0;word-break:break-all}
.code{display:inline-block;min-width:38px;font-weight:700}
.item{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--line);border-radius:8px;margin-bottom:8px;overflow:hidden}
.item.s-fail{border-left-color:var(--fail)}.item.s-warn{border-left-color:var(--warn)}.item.s-pass{border-left-color:var(--pass)}.item.s-info{border-left-color:var(--info)}
.head{display:flex;align-items:center;gap:10px;padding:10px 14px}
.head h3{font-size:15px;margin:0;flex:1;min-width:0}
.pill{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:99px;white-space:nowrap}
.p-pass{color:var(--pass);background:var(--pass-bg)}.p-warn{color:var(--warn);background:var(--warn-bg)}.p-fail{color:var(--fail);background:var(--fail-bg)}.p-info{color:var(--info);background:var(--info-bg)}
.sev{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}.sev-high{color:var(--fail)}
.body{padding:0 14px 12px;font-size:14px}.body p{margin:6px 0}
.cur{font-size:13px}
.s-pass .body p{color:var(--muted)}
body.hide-pass .s-pass{display:none}
.tabs{display:flex;gap:4px;flex-wrap:wrap;margin-top:12px;border-bottom:1px solid var(--line)}
.tab{background:transparent;color:var(--muted);border-radius:8px 8px 0 0;padding:8px 12px;font-weight:600;font-size:14px}
.tab.on{color:var(--ink);background:var(--card);border:1px solid var(--line);border-bottom-color:var(--card);margin-bottom:-1px}
.panel{display:none;position:relative;background:var(--card);border:1px solid var(--line);border-top:0;border-radius:0 0 8px 8px;padding:10px}
.panel.on{display:block}.panel pre{margin:0}
.copy{position:absolute;top:16px;right:16px;padding:4px 10px;font-size:12px}
.raw summary{cursor:pointer;font-weight:600}
.raw table{width:100%;border-collapse:collapse;margin-top:10px;font-size:13px;background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden}
.raw th,.raw td{text-align:left;vertical-align:top;padding:6px 10px;border-bottom:1px solid var(--line);font-family:ui-monospace,Menlo,Consolas,monospace;word-break:break-all}
.raw th{width:30%;color:var(--muted);font-weight:500}
footer{color:var(--muted);font-size:13px;margin:36px 0 48px;border-top:1px solid var(--line);padding-top:14px}
@media (max-width:560px){.scan{flex-direction:column}.facts{grid-template-columns:1fr}.facts dd{margin-bottom:6px}.grade{width:64px;height:64px;font-size:30px}}
CSS;
}

function hp_js()
{
    return <<<'JS'
(function () {
  'use strict';
  var hp = document.getElementById('hide-pass');
  if (hp) hp.addEventListener('change', function () { document.body.classList.toggle('hide-pass', hp.checked); });

  Array.prototype.forEach.call(document.querySelectorAll('.tab'), function (t) {
    t.addEventListener('click', function () {
      Array.prototype.forEach.call(document.querySelectorAll('.tab'), function (x) { x.classList.remove('on'); x.setAttribute('aria-selected', 'false'); });
      Array.prototype.forEach.call(document.querySelectorAll('.panel'), function (p) { p.classList.remove('on'); });
      t.classList.add('on'); t.setAttribute('aria-selected', 'true');
      document.getElementById(t.getAttribute('data-tab')).classList.add('on');
    });
  });

  function copy(text, btn) {
    var done = function () { var o = btn.textContent; btn.textContent = 'Copied'; setTimeout(function () { btn.textContent = o; }, 1500); };
    if (navigator.clipboard && window.isSecureContext) { navigator.clipboard.writeText(text).then(done); return; }
    var ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); done(); } catch (e) {} ta.remove();
  }
  Array.prototype.forEach.call(document.querySelectorAll('[data-copy],[data-copy-target]'), function (b) {
    b.addEventListener('click', function () {
      var t = b.getAttribute('data-copy-target');
      var text = t ? document.getElementById(t).textContent : b.getAttribute('data-copy');
      if (b.getAttribute('data-absolute')) text = new URL(text, location.href).href;
      copy(text, b);
    });
  });
})();
JS;
}

// ----------------------------------------------------------------------------
//  CLI mode
// ----------------------------------------------------------------------------

function hp_cli_main($argv)
{
    $o = array('json' => false, 'fail-on' => 'high', 'color' => true, 'allow_private' => false, 'proxy' => '', 'cacert' => '');
    $urls = array();
    foreach (array_slice($argv, 1) as $a) {
        if ($a === '--json') {
            $o['json'] = true;
        } elseif ($a === '--no-color') {
            $o['color'] = false;
        } elseif ($a === '--allow-private') {
            $o['allow_private'] = true;
        } elseif (strpos($a, '--fail-on=') === 0) {
            $o['fail-on'] = substr($a, 10);
        } elseif (strpos($a, '--proxy=') === 0) {
            $o['proxy'] = substr($a, 8);
        } elseif (strpos($a, '--cacert=') === 0) {
            $o['cacert'] = substr($a, 9);
        } elseif ($a === '-h' || $a === '--help') {
            echo "HeadPatrol " . HEADPATROL_VERSION . " - security headers scanner\n\n"
                . "Usage: php headpatrol.php [options] URL [URL...]\n\n"
                . "  --json             Output JSON (an array when several URLs are given)\n"
                . "  --fail-on=LEVEL    Exit 1 if a failed check is at least: high (default), medium, low, none\n"
                . "  --no-color         Plain output (also honours NO_COLOR)\n"
                . "  --allow-private    Allow private/internal addresses (for auditing your own intranet)\n"
                . "  --proxy=URL        Send requests through an HTTP proxy\n"
                . "  --cacert=FILE      Extra CA bundle for TLS verification\n\n"
                . "Exit codes: 0 ok, 1 failed checks at --fail-on level, 2 usage error, 3 scan error\n";
            return 0;
        } elseif ($a !== '' && $a[0] === '-') {
            fwrite(STDERR, "Unknown option: $a (try --help)\n");
            return 2;
        } else {
            $urls[] = $a;
        }
    }
    if (!$urls) {
        fwrite(STDERR, "Usage: php headpatrol.php [options] URL [URL...]  (try --help)\n");
        return 2;
    }
    $levels = array('high' => 3, 'medium' => 2, 'low' => 1, 'none' => 99);
    if (!isset($levels[$o['fail-on']])) {
        fwrite(STDERR, "--fail-on must be high, medium, low or none\n");
        return 2;
    }
    if ($o['color'] && (getenv('NO_COLOR') !== false || (function_exists('posix_isatty') && !posix_isatty(STDOUT)))) {
        $o['color'] = false;
    }
    $c = function ($code, $s) use ($o) {
        return $o['color'] ? "\033[{$code}m$s\033[0m" : $s;
    };
    $sym = array('pass' => $c('32', 'PASS'), 'warn' => $c('33', 'WARN'), 'fail' => $c('31;1', 'FAIL'), 'info' => $c('36', 'INFO'));

    $exit = 0;
    $all = array();
    foreach ($urls as $u) {
        $res = hp_scan($u, $o);
        if (isset($res['chain'])) {
            unset($res['chain']);
        }
        if (isset($res['error'])) {
            $exit = max($exit, 3);
            if ($o['json']) {
                $all[] = array('input' => $u, 'error' => $res['error']);
            } else {
                echo "\n" . $c('1', $u) . "\n  " . $c('31;1', 'ERROR') . '  ' . $res['error'] . "\n";
            }
            continue;
        }
        foreach ($res['results'] as $i) {
            if ($i['status'] === 'fail' && $levels[$i['severity']] >= $levels[$o['fail-on']]) {
                $exit = max($exit, 1);
            }
        }
        if ($o['json']) {
            $all[] = $res;
            continue;
        }
        echo "\n" . $c('1', 'HeadPatrol ' . HEADPATROL_VERSION) . '  ' . $res['final_url'] . "\n";
        echo '  HTTP ' . $res['http_version'] . ' ' . $res['status'] . ' · ' . $res['time_ms'] . ' ms' . ($res['ip'] ? ' · ' . $res['ip'] : '') . "\n";
        if ($res['notice'] !== '') {
            echo '  ' . $c('33', 'NOTE: ' . $res['notice']) . "\n";
        }
        if (count($res['redirects']) > 1) {
            foreach ($res['redirects'] as $r) {
                echo '  ' . $c('2', $r['status'] . ' ' . $r['url']) . "\n";
            }
        }
        $cat = '';
        foreach ($res['results'] as $i) {
            if ($i['category'] !== $cat) {
                $cat = $i['category'];
                echo "\n" . $c('1;4', $cat) . "\n";
            }
            $sev = in_array($i['status'], array('fail', 'warn'), true) ? ' ' . $c('2', '[' . $i['severity'] . ']') : '';
            echo '  ' . $sym[$i['status']] . '  ' . $i['title'] . $sev . "\n";
            if ($i['status'] !== 'pass') {
                echo '        ' . $c('2', 'current: ') . str_replace("\n", ', ', $i['current']) . "\n";
                echo '        ' . wordwrap($i['detail'], 92, "\n        ") . "\n";
                if ($i['snippet'] !== '') {
                    echo '        ' . $c('32', 'fix: ') . str_replace("\n", "\n             ", $i['snippet']) . "\n";
                }
            }
        }
        $gc = $res['score'] >= 80 ? '32;1' : ($res['score'] >= 60 ? '33;1' : '31;1');
        echo "\n" . $c($gc, 'Score: ' . $res['score'] . '/100  Grade: ' . $res['grade'])
            . "   ({$res['counts']['fail']} failed, {$res['counts']['warn']} warnings, {$res['counts']['pass']} passed)\n";
        if ($res['recommended_headers']) {
            echo "\n" . $c('1', 'Suggested headers') . "\n";
            foreach ($res['recommended_headers'] as $n => $v) {
                echo '  ' . $n . ': ' . $v . "\n";
            }
        }
    }
    if ($o['json']) {
        echo json_encode(count($all) === 1 ? $all[0] : $all, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
    } else {
        echo "\n";
    }
    return $exit;
}

// ----------------------------------------------------------------------------
//  Entry point (tests define HEADPATROL_NO_MAIN to load the functions only)
// ----------------------------------------------------------------------------

if (defined('HEADPATROL_NO_MAIN')) {
    return;
}
if (HEADPATROL_IS_CLI) {
    exit(hp_cli_main(isset($argv) ? $argv : array()));
}
hp_web_main();
