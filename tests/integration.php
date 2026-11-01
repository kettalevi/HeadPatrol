<?php
/**
 * End-to-end test against the local fixture server.
 * Start it first:  php -S 127.0.0.1:8099 tests/fixture/router.php
 * Then run:        php tests/integration.php
 */
define('HEADPATROL_NO_MAIN', true);
define('HEADPATROL_ALLOWED_PORTS', '80,443,8099');
require __DIR__ . '/../headpatrol.php';

$fail = 0;
function expect($cond, $label)
{
    global $fail;
    echo ($cond ? '  ok   ' : '  FAIL ') . $label . "\n";
    if (!$cond) {
        $fail++;
    }
}
function find($res, $id)
{
    foreach ($res['results'] as $i) {
        if ($i['id'] === $id) {
            return $i;
        }
    }
    return null;
}

$intranet = array('allow_private' => true);

$s = hp_scan('http://127.0.0.1:8099/strong', $intranet);
expect(!isset($s['error']), 'strong page scans');
expect(find($s, 'csp_scripts')['status'] === 'pass', 'strong page: nonce + strict-dynamic CSP passes');
expect(find($s, 'cookie_0')['status'] === 'pass', 'strong page: __Host- cookie passes');

$t = microtime(true);
$w = hp_scan('http://127.0.0.1:8099/weak', $intranet);
$ms = (microtime(true) - $t) * 1000;
expect($w['grade'] === 'F', 'weak page grades F');
expect(find($w, 'cors')['status'] === 'fail', 'weak page: reflected CORS with credentials is caught');
expect($ms < 2000, 'large body is not downloaded (' . round($ms) . ' ms)');

$r = hp_scan('http://127.0.0.1:8099/r1', $intranet);
expect(count($r['redirects']) === 3 && $r['final_url'] === 'http://127.0.0.1:8099/weak', 'relative + absolute redirects are followed');

$l = hp_scan('http://127.0.0.1:8099/loop', $intranet);
expect(isset($l['error']) && strpos($l['error'], 'redirects') !== false, 'redirect loops stop');

$n = hp_scan('http://127.0.0.1:8099/missing', $intranet);
expect(isset($n['notice']) && strpos($n['notice'], '404') !== false, 'error pages carry a notice');

$p = hp_scan('http://127.0.0.1:8099/strong', array());
expect(isset($p['error']) && strpos($p['error'], 'private') !== false, 'public mode refuses the local server');

echo $fail ? "\n$fail integration test(s) failed\n" : "\nAll integration tests passed\n";
exit($fail ? 1 : 0);
