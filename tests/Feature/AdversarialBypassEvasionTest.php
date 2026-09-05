<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Mixudev\SecurityDefense\Middleware\RequestThreatScanner;
use Mixudev\SecurityDefense\Tests\TestCase;

/**
 * Realistic and Advanced Adversarial Bypass / Mutation Testing.
 * Tests evasive payloads, encoding tricks, nested objects, and prototype-like structures.
 */
class AdversarialBypassEvasionTest extends TestCase
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
            Route::post('/api/profile', static fn (Request $request) => response()->json(['status' => 'ok', 'data' => $request->all()]));
            Route::get('/api/search', static fn (Request $request) => response()->json(['status' => 'ok', 'q' => $request->query('q')]));
            Route::post('/api/upload-comment', static fn (Request $request) => response()->json(['status' => 'ok']));
        });
        \Illuminate\Support\Facades\Route::getRoutes()->refreshNameLookups();
        \Illuminate\Support\Facades\Route::getRoutes()->refreshActionLookups();
    }

    public function test_deeply_nested_json_payload_attacks_are_intercepted(): void
    {
        $payload = [
            'user' => [
                'metadata' => [
                    'preferences' => [
                        'settings' => [
                            'theme' => "dark'; DROP TABLE users;--",
                        ],
                    ],
                ],
            ],
        ];

        $response = $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.51'])
            ->postJson('/api/profile', $payload);

        $this->assertSame(403, $response->getStatusCode());
    }

    public function test_mixed_case_and_tab_newline_evasion_sqli_is_blocked(): void
    {
        $evasions = [
            "1' \t\r\nUnIoN\nSeLeCt null, password FROM users--",
            "1' \t  oR   \t  '1' = '1",
            "1'; \n\t DrOp \t TaBlE users;--",
            "admin'--\r\n",
        ];

        foreach ($evasions as $index => $vector) {
            $ip = '198.51.100.' . (60 + $index);
            $response = $this->withServerVariables(['REMOTE_ADDR' => $ip])
                ->postJson('/api/profile', ['query' => $vector]);

            $this->assertSame(403, $response->getStatusCode(), "Failed blocking evasion vector: {$vector}");
        }
    }

    public function test_obfuscated_xss_vectors_are_blocked(): void
    {
        $xssVectors = [
            "<ScRiPt>alert('xss')</sCrIpT>",
            "<img src='invalid' onerror=alert(document.cookie)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "<body onload=alert('pwn')>",
            "<iframe src=javascript:alert('xss')>",
        ];

        foreach ($xssVectors as $index => $vector) {
            $ip = '198.51.100.' . (70 + $index);
            $response = $this->withServerVariables(['REMOTE_ADDR' => $ip])
                ->postJson('/api/upload-comment', ['comment' => $vector]);

            $this->assertSame(403, $response->getStatusCode(), "Failed blocking XSS vector: {$vector}");
        }
    }

    public function test_path_traversal_windows_and_linux_variations_are_blocked(): void
    {
        $traversals = [
            '..\\..\\..\\windows\\win.ini',
            '../../../../etc/passwd',
            '..%2f..%2fetc%2fpasswd',
            '..\\..\\boot.ini',
        ];

        foreach ($traversals as $index => $vector) {
            $ip = '198.51.100.' . (80 + $index);
            $response = $this->withServerVariables(['REMOTE_ADDR' => $ip])
                ->get('/api/search?q=' . $vector);

            $this->assertSame(403, $response->getStatusCode(), "Failed blocking Traversal vector: {$vector}");
        }
    }

    public function test_command_injection_chained_operators_are_blocked(): void
    {
        $commands = [
            '; cat /etc/passwd',
            '| whoami',
            '&& id',
            '`uname -a`',
            '; powershell -enc test',
            '& cmd.exe /c dir',
        ];

        foreach ($commands as $index => $vector) {
            $ip = '198.51.100.' . (90 + $index);
            $response = $this->withServerVariables(['REMOTE_ADDR' => $ip])
                ->postJson('/api/profile', ['input' => $vector]);

            $this->assertSame(403, $response->getStatusCode(), "Failed blocking RCE vector: {$vector}");
        }
    }

    public function test_legitimate_content_does_not_trigger_false_positives(): void
    {
        $cleanInputs = [
            'Hello world this is a normal comment',
            'How to select items in a shop dropdown',
            'The weather is cloudy and 24 degrees today',
            'My email is user@example.com and phone is +62812345678',
            'Price: $49.99 for 2 items (discount 10%)',
            'Can you drop by my house later?',
        ];

        foreach ($cleanInputs as $index => $clean) {
            $response = $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.' . ($index + 1)])
                ->post('/api/profile', ['text' => $clean]);

            $this->assertSame(200, $response->getStatusCode(), "Legitimate text falsely blocked: {$clean}");
        }
    }
}
