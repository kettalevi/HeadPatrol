<?php
/**
 * HeadPatrol test suite. No dependencies: php tests/run.php
 * Network-free: covers SSRF defences, URL handling and the analysers.
 */
define('HEADPATROL_NO_MAIN', true);
require __DIR__ . '/../headpatrol.php';

$pass = 0;
$fail = 0;
function check($cond, $label)
{
    global $pass, $fail;
    if ($cond) {
        $pass++;
    } else {
        $fail++;
        echo "  FAIL: $label\n";
    }
}

// ---------------------------------------------------------------- IP classification
echo "IP classification\n";
$private = array(
    '127.0.0.1', '127.255.255.254', '10.0.0.1', '172.16.0.1', '172.31.255.255', '192.168.1.1',
    '169.254.169.254', // cloud metadata
    '100.64.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255', '198.18.0.1', '192.0.2.1', '203.0.113.9',
    '::1', '::', 'fe80::1', 'fc00::1', 'fd12:3456::1', 'ff02::1',
    '::ffff:127.0.0.1', '::ffff:169.254.169.254', '::ffff:10.0.0.1', '::127.0.0.1',
    '2001:db8::1', '2002:7f00:1::1', '2001:0:4136:e378:8000:63bf:3fff:fdd2', '64:ff9b::7f00:1',
    'fd00:ec2::254', // AWS IPv6 metadata
    'not-an-ip', '',
);
foreach ($private as $ip) {
    check(!hp_ip_is_public($ip), "$ip must be refused");
}
$public = array('8.8.8.8', '1.1.1.1', '140.82.112.3', '172.32.0.1', '100.128.0.1', '2606:4700:4700::1111', '2a00:1450:4001::200e', '::ffff:8.8.8.8');
foreach ($public as $ip) {
    check(hp_ip_is_public($ip), "$ip must be allowed");
}

// ---------------------------------------------------------------- URL normalisation
echo "URL normalisation\n";
$reject = array(
    'file:///etc/passwd', 'gopher://example.com/', 'ftp://example.com/', 'dict://example.com:11211/',
    'javascript:alert(1)', 'data:text/html,hi', 'php://filter/resource=/etc/passwd',
    'http://user:pass@example.com/', 'http://user@example.com/',
    'http://2130706433/', 'http://0x7f000001/', 'http://0x7f.0.0.1/', 'http://0177.0.0.1/', 'http://127.1/', 'http://017700000001/',
    'http://example.com:22/', 'http://example.com:6379/', 'https://example.com:8443/',
    'localhost', 'http://intranet/', 'http://exa mple.com/', "http://example.com/\r\nX-Injected: 1",
    'http://example.com\\@evil.com/', 'http://[::1', 'http://[not:ipv6]/', '', str_repeat('a', 3000),
    'http://-bad-.com/', 'http://exa_mple.com/',
);
foreach ($reject as $u) {
    check(is_string(hp_normalize_url($u)), 'must reject ' . substr($u, 0, 60));
}
$cases = array(
    'example.com' => 'https://example.com/',
    'EXAMPLE.com.' => 'https://example.com/',
    'http://example.com' => 'http://example.com/',
    'https://example.com:443/a?b=1#frag' => 'https://example.com/a?b=1',
    'example.com:80/x' => 'https://example.com:80/x',
    'https://example.com/p a' => null, // spaces rejected
    'https://[2606:4700:4700::1111]/' => 'https://[2606:4700:4700::1111]/',
    'https://example.com/ünï' => 'https://example.com/%C3%BCn%C3%AF',
);
foreach ($cases as $in => $want) {
    $got = hp_normalize_url($in);
    if ($want === null) {
        check(is_string($got), "must reject $in");
    } else {
        check(is_array($got) && $got['url'] === $want, "$in -> $want (got " . (is_array($got) ? $got['url'] : $got) . ')');
    }
}
if (function_exists('idn_to_ascii')) {
    $got = hp_normalize_url('https://bücher.example/');
    check(is_array($got) && $got['host'] === 'xn--bcher-kva.example', 'IDN converts to punycode');
}

// ---------------------------------------------------------------- Target vetting (literal IPs: no DNS needed)
echo "Target vetting\n";
foreach (array('http://127.0.0.1/', 'http://169.254.169.254/latest/meta-data/', 'http://[::1]/', 'http://10.1.2.3/', 'http://[::ffff:127.0.0.1]/') as $u) {
    $p = hp_normalize_url($u);
    $v = is_array($p) ? hp_vet_target($p, false) : array('error' => $p);
    check(isset($v['error']), "vet must block $u");
    $f = hp_fetch($u, array());
    check($f['error'] !== '' && $f['status'] === 0, "fetch must refuse $u without connecting");
}
$p = hp_normalize_url('http://127.0.0.1/');
$v = hp_vet_target($p, true);
check(isset($v['ip']) && $v['ip'] === '127.0.0.1', 'allow_private lets intranet scans through');

// ---------------------------------------------------------------- Redirect resolution
echo "Redirect resolution\n";
$base = 'https://example.com/a/b/page?x=1';
$loc = array(
    'https://other.com/' => 'https://other.com/',
    '//cdn.example.com/x' => 'https://cdn.example.com/x',
    '/root' => 'https://example.com/root',
    'rel' => 'https://example.com/a/b/rel',
    '?q=2' => 'https://example.com/a/b/page?q=2',
    '' => $base,
    'http://127.0.0.1/' => 'http://127.0.0.1/', // resolved here, then refused by hp_fetch's vetting
);
foreach ($loc as $l => $want) {
    check(hp_resolve_location($base, $l) === $want, "Location '$l' -> $want");
}
check(hp_fetch(hp_resolve_location($base, 'http://169.254.169.254/'), array())['error'] !== '', 'redirect target to metadata is refused');

// ---------------------------------------------------------------- Analysis
echo "Analysis\n";
function fake($headers, $url = 'https://example.com/')
{
    return array('url' => $url, 'status' => 200, 'http_version' => '2', 'headers' => $headers, 'ip' => '93.184.215.14', 'time_ms' => 50, 'error' => '', 'cert_error' => '');
}
function statusOf($report, $id)
{
    foreach ($report->items as $i) {
        if ($i['id'] === $id) {
            return $i['status'];
        }
    }
    return null;
}
$redirectOk = array('url' => 'http://example.com/', 'status' => 301, 'http_version' => '1.1', 'headers' => array(array('Location', 'https://example.com/')), 'ip' => '', 'time_ms' => 1, 'error' => '', 'cert_error' => '');

$strong = fake(array(
    array('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload'),
    array('Content-Security-Policy', "default-src 'self'; script-src 'nonce-abc' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"),
    array('X-Content-Type-Options', 'nosniff'),
    array('Referrer-Policy', 'strict-origin-when-cross-origin'),
    array('Permissions-Policy', 'camera=()'),
    array('Cross-Origin-Opener-Policy', 'same-origin'),
    array('Set-Cookie', '__Host-sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax'),
    array('Server', 'nginx'),
));
$r = hp_analyze($strong, array($strong), $redirectOk);
$c = $r->counts();
check($c['fail'] === 0 && $c['warn'] === 0, 'strong site has no fails or warnings (got ' . json_encode($c) . ')');
check(HP_Report::grade(max(0, 100 - $r->penalty()), $c) === 'A+', 'strong site grades A+');
check(!$r->recommend, 'strong site needs no recommended headers');

$weak = fake(array(
    array('Server', 'Apache/2.4.29 (Ubuntu)'),
    array('X-Powered-By', 'PHP/7.2.1'),
    array('Set-Cookie', 'PHPSESSID=abc; path=/'),
    array('Access-Control-Allow-Origin', HEADPATROL_PROBE_ORIGIN),
    array('Access-Control-Allow-Credentials', 'true'),
    array('X-XSS-Protection', '1; mode=block'),
));
$httpServes = array('url' => 'http://example.com/', 'status' => 200, 'http_version' => '1.1', 'headers' => array(), 'ip' => '', 'time_ms' => 1, 'error' => '', 'cert_error' => '');
$r = hp_analyze($weak, array($weak), $httpServes);
foreach (array('hsts' => 'fail', 'csp' => 'fail', 'framing' => 'fail', 'xcto' => 'fail', 'cors' => 'fail', 'cookie_0' => 'fail', 'version_leak' => 'warn', 'http_redirect' => 'fail', 'x_xss' => 'info') as $id => $want) {
    check(statusOf($r, $id) === $want, "weak site: $id is $want (got " . var_export(statusOf($r, $id), true) . ')');
}
check(HP_Report::grade(max(0, 100 - $r->penalty()), $r->counts()) === 'F', 'weak site grades F');
check(isset($r->recommend['Content-Security-Policy'], $r->recommend['Strict-Transport-Security']), 'weak site gets CSP and HSTS recommendations');

// CSP details
$csp = function ($policy) {
    $r = new HP_Report();
    hp_check_csp($r, array(array('Content-Security-Policy', $policy)));
    return $r;
};
check(statusOf($csp("default-src 'self' 'unsafe-inline'"), 'csp_scripts') === 'fail', "unsafe-inline without nonce fails");
check(statusOf($csp("script-src 'self' 'unsafe-inline' 'nonce-xyz'; object-src 'none'; base-uri 'self'"), 'csp_scripts') === 'pass', 'unsafe-inline with nonce is ignored by browsers -> pass');
check(statusOf($csp("script-src https: 'self'"), 'csp_scripts') === 'fail', 'https: wildcard fails');
check(statusOf($csp("script-src *"), 'csp_scripts') === 'fail', '* wildcard fails');
check(statusOf($csp("script-src 'self' http://cdn.example.com"), 'csp_scripts') === 'warn', 'plain http source warns');
check(statusOf($csp("img-src 'self'"), 'csp_scripts') === 'fail', 'no script-src/default-src fails');
check(statusOf($csp("default-src 'self' 'unsafe-eval'"), 'csp_eval') === 'warn', 'unsafe-eval warns');
check(statusOf($csp("default-src 'self'"), 'csp_object') === 'warn', 'object-src not none warns');
check(statusOf($csp("default-src 'none'"), 'csp_object') === 'pass', "default-src 'none' covers object-src");
$ro = new HP_Report();
hp_check_csp($ro, array(array('Content-Security-Policy-Report-Only', "default-src 'self'")));
check(statusOf($ro, 'csp') === 'warn', 'report-only CSP warns');

// CORS variants
foreach (array('*' => 'info', 'https://app.example.com' => 'pass', 'null' => 'warn') as $v => $want) {
    $r = hp_analyze(fake(array(array('Access-Control-Allow-Origin', $v))), array(fake(array())), $redirectOk);
    check(statusOf($r, 'cors') === $want, "ACAO $v -> $want");
}

// Cookies
$ck = function ($raw, $https = true) {
    $r = new HP_Report();
    hp_check_cookie($r, $raw, $https, 0);
    return $r->items[0];
};
check($ck('sid=1; Secure; HttpOnly; SameSite=Strict')['status'] === 'pass', 'fully flagged cookie passes');
check($ck('theme=dark; Secure; SameSite=Lax')['status'] === 'info', 'non-sensitive cookie without HttpOnly is info');
check($ck('x=1; SameSite=None; HttpOnly')['status'] === 'fail', 'SameSite=None without Secure fails');
check($ck('auth_token=1; HttpOnly; SameSite=Lax')['status'] === 'fail', 'sensitive cookie without Secure on https fails');
check(strpos($ck('sid=SECRETVALUE; Secure')['current'] . $ck('sid=SECRETVALUE; Secure')['detail'], 'SECRETVALUE') === false, 'cookie values are never shown');

// HSTS variants
$r = hp_analyze(fake(array(array('Strict-Transport-Security', 'max-age=300'))), array(fake(array())), $redirectOk);
check(statusOf($r, 'hsts') === 'warn', 'short HSTS max-age warns');
$r = hp_analyze(fake(array(), 'http://example.com/'), array(fake(array(), 'http://example.com/')), $httpServes);
check(statusOf($r, 'https') === 'fail' && statusOf($r, 'hsts') === 'info', 'plain HTTP site: https fails, hsts info');

// http:// input whose redirect chain ends on HTTPS (via an intermediate http hop)
$firstHop = array('url' => 'http://example.com/', 'status' => 301, 'http_version' => '1.1', 'headers' => array(array('Location', 'http://www.example.com/')), 'ip' => '', 'time_ms' => 1, 'error' => '', 'cert_error' => '', 'reaches_https' => true);
$r = hp_analyze(fake(array()), array($firstHop, fake(array())), $firstHop);
check(statusOf($r, 'http_redirect') === 'pass', 'multi-hop HTTP -> HTTPS chain passes');
$firstHop['reaches_https'] = false;
$r = hp_analyze(fake(array(), 'http://www.example.com/'), array($firstHop), $firstHop);
check(statusOf($r, 'http_redirect') === 'fail', 'chain that never reaches HTTPS fails');

// Cert error
$bad = fake(array());
$bad['cert_error'] = 'SSL certificate problem: self-signed certificate';
$r = hp_analyze($bad, array($bad), $redirectOk);
check(statusOf($r, 'certificate') === 'fail', 'certificate errors fail');

// Snippets escape properly
$s = hp_config_snippets(array('Content-Security-Policy' => "default-src 'self'", 'X-Test' => 'a"b<c>'));
check(strpos($s['PHP'], "header('Content-Security-Policy: default-src \\'self\\'');") !== false, 'PHP snippet escapes quotes');
check(strpos($s['IIS'], 'a&quot;b&lt;c&gt;') !== false, 'IIS snippet XML-escapes values');
check(strpos($s['nginx'], 'add_header X-Test "a\\"b<c>" always;') !== false, 'nginx snippet escapes double quotes');

// Header text sanitising
check(hp_clean("ok\x00\x1b[31mred\xff") === 'ok??[31mred?', 'control and non-ASCII bytes are neutralised');

echo "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
