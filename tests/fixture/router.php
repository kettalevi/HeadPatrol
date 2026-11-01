<?php
// Test fixture server: php -S 127.0.0.1:8099 tests/fixture/router.php
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
switch ($path) {
    case '/strong':
        header('Strict-Transport-Security: max-age=63072000; includeSubDomains');
        header("Content-Security-Policy: default-src 'self'; script-src 'nonce-t3st' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: no-referrer');
        header('Permissions-Policy: camera=()');
        header('Cross-Origin-Opener-Policy: same-origin');
        header('Set-Cookie: __Host-sid=1; Path=/; Secure; HttpOnly; SameSite=Lax');
        echo 'strong';
        break;
    case '/weak':
        header('X-Powered-By: PHP/5.6.40');
        header('Set-Cookie: PHPSESSID=abc; path=/');
        if (isset($_SERVER['HTTP_ORIGIN'])) {
            header('Access-Control-Allow-Origin: ' . $_SERVER['HTTP_ORIGIN']);
            header('Access-Control-Allow-Credentials: true');
        }
        echo str_repeat('body ', 100000); // large body: HeadPatrol must not download it
        break;
    case '/r1':
        header('Location: /r2', true, 302);
        break;
    case '/r2':
        header('Location: http://127.0.0.1:8099/weak', true, 301);
        break;
    case '/loop':
        header('Location: /loop', true, 302);
        break;
    case '/to-metadata':
        header('Location: http://169.254.169.254/latest/meta-data/', true, 302);
        break;
    default:
        http_response_code(404);
        echo 'not found';
}
