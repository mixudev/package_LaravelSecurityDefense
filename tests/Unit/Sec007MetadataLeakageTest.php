<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\Rules\BruteForceRule;
use Mixudev\SecurityDefense\Rules\SessionFingerprintRule;
use Mixudev\SecurityDefense\Services\ThreatTelemetryRecorder;
use Mixudev\SecurityDefense\Sources\RequestThreatSource;
use Mixudev\SecurityDefense\Support\Sanitizer;
use Mixudev\SecurityDefense\Tests\TestCase;

class Sec007MetadataLeakageTest extends TestCase
{
    public function test_request_source_does_not_leak_secrets_into_event(): void
    {
        $request = \Illuminate\Http\Request::create('/login?api_key=sk_live_secret&token=secret_token_value', 'POST', [
            'password' => 'hunter2',
            'email' => 'user@example.com',
        ]);
        $request->headers->set('Authorization', 'Bearer real-super-secret-token');
        $request->headers->set('x-forwarded-for', '10.0.0.1, 10.0.0.2');
        $request->headers->set('cf-connecting-ip', '203.0.113.9');

        $event = (new RequestThreatSource($request))->toSecurityEvent();
        $json = json_encode($event->toArray());

        $this->assertStringNotContainsString('sk_live_secret', $json);
        $this->assertStringNotContainsString('secret_token_value', $json);
        $this->assertStringNotContainsString('hunter2', $json);
        $this->assertStringNotContainsString('real-super-secret-token', $json);
        $this->assertStringNotContainsString('user@example.com', $json);
        $this->assertStringNotContainsString('10.0.0', json_encode($event->metadata['headers']));
        $this->assertStringNotContainsString('203.0.113', json_encode($event->metadata['headers']));
        $this->assertStringNotContainsString('api_key=', $json);
        $this->assertStringNotContainsString('token=', $json);
    }

    public function test_request_source_redacts_dashboard_route_identifiers(): void
    {
        config()->set('app.key', 'base64:' . base64_encode(random_bytes(32)));
        $capability = app(\Mixudev\SecurityDefense\Support\DashboardCapability::class)->issue('test-session');

        $request = \Illuminate\Http\Request::create('/' . $capability . '/epistemic', 'GET');
        $request->setRouteResolver(fn () => new class {
            public function getName(): string { return 'security-defense.epistemic'; }
            public function parameter($k) { return null; }
        });
        $event = (new RequestThreatSource($request))->toSecurityEvent();
        $json = json_encode($event->toArray());

        $this->assertStringNotContainsString($capability, $json);
        $this->assertStringContainsString('[dashboard-route', $json);
    }

    public function test_request_source_hashes_identifier_from_email(): void
    {
        $request = \Illuminate\Http\Request::create('/test', 'POST', ['email' => 'user@example.com']);
        $event = (new RequestThreatSource($request))->toSecurityEvent();

        $this->assertSame(hash('sha256', strtolower('user@example.com')), $event->identifier);
        $this->assertStringNotContainsString('user@example.com', $event->identifier);
    }

    public function test_request_source_truncates_control_characters(): void
    {
        $request = \Illuminate\Http\Request::create('/test', 'POST', [
            'data' => "line1\r\nline2\x00\x08injection",
        ]);
        $event = (new RequestThreatSource($request))->toSecurityEvent();
        $json = json_encode($event->toArray());

        $this->assertStringNotContainsString("\r", $json);
        $this->assertStringNotContainsString("\n", $json);
        $this->assertStringNotContainsString("\x00", $json);
    }

    public function test_request_source_strips_empty_hash_keys(): void
    {
        $request = \Illuminate\Http\Request::create('/test', 'GET');
        $event = (new RequestThreatSource($request))->toSecurityEvent();

        $this->assertArrayNotHasKey('x_forwarded_for_hash', $event->metadata['headers']);
        $this->assertArrayNotHasKey('cf_connecting_ip_hash', $event->metadata['headers']);
    }

    public function test_request_source_bounds_extra_metadata(): void
    {
        $request = \Illuminate\Http\Request::create('/test', 'GET');
        $source = new RequestThreatSource($request, extraMetadata: array_fill(0, 100, ['k' => str_repeat('v', 100)]));
        $event = $source->toSecurityEvent();

        $this->assertLessThanOrEqual(32, count($event->metadata));
    }

    public function test_brute_force_metadata_does_not_leak_identifiers(): void
    {
        config()->set('security-defense.detection.rules.brute_force.threshold', 2);
        $rule = app(BruteForceRule::class);
        $email = 'victim@example.com';
        $event = new SecurityEvent(ip: '192.168.1.1', identifier: $email, eventType: 'LoginFailed');

        $rule->evaluate($event);
        $threat = $rule->evaluate($event);

        $this->assertNotNull($threat);
        $json = json_encode($threat->metadata);

        $this->assertStringNotContainsString('victim@example.com', $json);
        $this->assertArrayNotHasKey('target', $threat->metadata);
        $this->assertArrayHasKey('target_hash', $threat->metadata);
        $this->assertEquals(64, strlen($threat->metadata['target_hash']));
        $this->assertEquals(64, strlen($threat->metadata['user_agent_hash']));
    }

    public function test_session_fingerprint_metadata_does_not_leak_user_agents(): void
    {
        $rule = app(SessionFingerprintRule::class);
        $session = 'sess_hijack_test_secret_abc';

        $baseline = new SecurityEvent(
            ip: '203.0.113.10',
            identifier: 'user_42',
            eventType: 'AuthenticatedRequest',
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0',
            metadata: ['session_id' => $session]
        );
        $rule->evaluate($baseline);

        $hijack = new SecurityEvent(
            ip: '198.51.100.99',
            identifier: 'user_42',
            eventType: 'AuthenticatedRequest',
            userAgent: 'curl/7.88.1',
            metadata: ['session_id' => $session]
        );
        $threat = $rule->evaluate($hijack);

        $this->assertNotNull($threat);
        $json = json_encode($threat->metadata);

        $this->assertStringNotContainsString('curl/7.88.1', $json);
        $this->assertStringNotContainsString('Mozilla/5.0', $json);
        $this->assertArrayHasKey('current_ua_hash', $threat->metadata);
        $this->assertArrayHasKey('initial_ua_hash', $threat->metadata);
        $this->assertEquals(64, strlen($threat->metadata['current_ua_hash']));
        $this->assertEquals(64, strlen($threat->metadata['initial_ua_hash']));

        $this->assertStringNotContainsString($session, $json);
        $this->assertEquals(hash('sha256', $session), $threat->metadata['session_hash']);
    }

    public function test_sanitizer_redacts_inline_secret_patterns(): void
    {
        $input = 'Authorization: Bearer sk_live_abc123, api_key: secret_key_99, password=badpwd';
        $cleaned = Sanitizer::cleanString($input);

        $this->assertStringNotContainsString('sk_live_abc123', $cleaned);
        $this->assertStringNotContainsString('secret_key_99', $cleaned);
        $this->assertStringNotContainsString('badpwd', $cleaned);
        $this->assertStringContainsString('[REDACTED]', $cleaned);
    }

    public function test_telemetry_recorder_metadata_is_sanitized_and_bounded(): void
    {
        $manager = app(\Mixudev\SecurityDefense\Services\SecurityDefenseManager::class);
        $recorder = new ThreatTelemetryRecorder($manager);

        $request = \Illuminate\Http\Request::create('/test?api_token=secret_val&password=badpw', 'GET');
        $request->headers->set('Authorization', 'Bearer leaked-token-123');

        $threat = $recorder->handleDetectedAnomaly(
            $request,
            'sqli',
            "UNION SELECT * FROM users WHERE token = 'stolen_abc' AND password = 'leaked'",
            'body'
        );

        $json = json_encode($threat->metadata);
        $this->assertStringNotContainsString('secret_val', $json);
        $this->assertStringNotContainsString('badpw', $json);
        $this->assertStringNotContainsString('leaked-token-123', $json);
        $this->assertStringNotContainsString('stolen_abc', $json);
        $this->assertStringNotContainsString('leaked', $json);
    }

    public function test_metadata_bounded_for_large_payloads(): void
    {
        $bigMetadata = array_fill(0, 200, ['key' => str_repeat('x', 200)]);
        $bounded = Sanitizer::bound($bigMetadata);

        $this->assertArrayHasKey('_telemetry_warning', $bounded);
        $this->assertArrayHasKey('preview', $bounded);
    }
}
