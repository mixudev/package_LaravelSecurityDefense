<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\Rules\BruteForceRule;
use Mixudev\SecurityDefense\Rules\CredentialStuffingRule;
use Mixudev\SecurityDefense\Rules\DistributedSprayRule;
use Mixudev\SecurityDefense\Rules\PathReconnaissanceRule;
use Mixudev\SecurityDefense\Rules\RateLimitBypassRule;
use Mixudev\SecurityDefense\Rules\UserAgentAnomalyRule;
use Mixudev\SecurityDefense\Tests\TestCase;

class SecurityFixRegressionTest extends TestCase
{
    public function test_brute_force_atomic_counter_does_not_rely_on_read_window(): void
    {
        config()->set('security-defense.detection.rules.brute_force.threshold', 3);
        config()->set('security-defense.detection.rules.brute_force.window', 60);

        $rule = app(BruteForceRule::class);

        // Simulate concurrent requests: each evaluate is independent, counter must accumulate
        $event = new SecurityEvent(ip: '192.168.1.100', identifier: 'victim@example.com', eventType: 'LoginFailed');

        $this->assertNull($rule->evaluate($event));
        $this->assertNull($rule->evaluate($event));
        $threat = $rule->evaluate($event);
        $this->assertNotNull($threat);
        $this->assertEquals(3, $threat->metadata['attempt_count']);
    }

    public function test_credential_stuffing_hashes_identifiers_in_metadata(): void
    {
        config()->set('security-defense.detection.rules.credential_stuffing.threshold', 2);
        config()->set('security-defense.detection.rules.credential_stuffing.window', 60);

        $rule = app(CredentialStuffingRule::class);

        $rule->evaluate(new SecurityEvent(ip: '45.33.32.1', identifier: 'user1.example.com', eventType: 'LoginFailed'));
        $threat = $rule->evaluate(new SecurityEvent(ip: '45.33.32.1', identifier: 'user2.example.com', eventType: 'LoginFailed'));

        $this->assertNotNull($threat);
        $this->assertArrayNotHasKey('sample_identifiers', $threat->metadata);
        $this->assertArrayHasKey('sample_identifiers_hashed', $threat->metadata);
        foreach ($threat->metadata['sample_identifiers_hashed'] as $hash) {
            $this->assertEquals(64, strlen($hash)); // SHA-256 hex
            $this->assertStringNotContainsString('example.com', $hash);
        }
        // Plaintext identifiers must not be present
        $this->assertStringNotContainsString('user1', json_encode($threat->metadata['sample_identifiers_hashed']));
    }

    public function test_distributed_spray_hashes_ips_in_metadata(): void
    {
        config()->set('security-defense.detection.rules.distributed_spray.threshold', 2);
        config()->set('security-defense.detection.rules.distributed_spray.window', 60);

        $rule = app(DistributedSprayRule::class);

        $rule->evaluate(new SecurityEvent(ip: '10.0.0.1', identifier: 'admin', eventType: 'LoginFailed'));
        $threat = $rule->evaluate(new SecurityEvent(ip: '10.0.0.2', identifier: 'admin', eventType: 'LoginFailed'));

        $this->assertNotNull($threat);
        $this->assertArrayNotHasKey('sample_ips', $threat->metadata);
        $this->assertArrayHasKey('sample_ips_hashed', $threat->metadata);
        foreach ($threat->metadata['sample_ips_hashed'] as $hash) {
            $this->assertEquals(64, strlen($hash));
        }
        $json = json_encode($threat->metadata['sample_ips_hashed']);
        $this->assertStringNotContainsString('10.0.0', $json);
    }

    public function test_user_agent_rule_flags_empty_ua_when_configured(): void
    {
        config()->set('security-defense.detection.rules.user_agent_anomaly.block_empty_user_agent', true);

        $rule = app(UserAgentAnomalyRule::class);
        $event = new SecurityEvent(
            ip: '1.2.3.4',
            identifier: 'guest',
            eventType: 'HttpRequestTelemetry',
            userAgent: ''
        );

        $threat = $rule->evaluate($event);
        $this->assertNotNull($threat);
        $this->assertEquals('empty_ua', $threat->metadata['detected_tool']);
    }

    public function test_user_agent_rule_ignores_empty_ua_when_not_configured(): void
    {
        config()->set('security-defense.detection.rules.user_agent_anomaly.block_empty_user_agent', false);

        $rule = app(UserAgentAnomalyRule::class);
        $event = new SecurityEvent(
            ip: '1.2.3.4',
            identifier: 'guest',
            eventType: 'HttpRequestTelemetry',
            userAgent: ''
        );

        $this->assertNull($rule->evaluate($event));
    }

    public function test_request_threat_source_hashes_headers(): void
    {
        $request = \Illuminate\Http\Request::create('/test', 'GET');
        $request->headers->set('x-forwarded-for', '10.0.0.5, 10.0.0.6, 10.0.0.7, 10.0.0.8, 10.0.0.9, 10.0.0.10');
        $request->headers->set('cf-connecting-ip', '203.0.113.9');
        $request->headers->set('origin', 'https://internal.admin.example.com');
        $request->headers->set('referer', 'https://internal.admin.example.com/secret-token-page');

        $source = new \Mixudev\SecurityDefense\Sources\RequestThreatSource($request);
        $event = $source->toSecurityEvent();

        $headers = $event->metadata['headers'];
        // Sensitive raw headers must not be present
        $this->assertArrayNotHasKey('x-forwarded-for', $headers);
        $this->assertArrayNotHasKey('origin', $headers);
        $this->assertArrayNotHasKey('referer', $headers);
        // Hashed versions present
        $this->assertArrayHasKey('x_forwarded_for_hash', $headers);
        $this->assertEquals(64, strlen($headers['x_forwarded_for_hash']));
        $this->assertStringNotContainsString('10.0.0', $headers['x_forwarded_for_hash']);
        $this->assertStringNotContainsString('internal.admin', json_encode($headers));
    }

    public function test_path_recon_atomic_counter(): void
    {
        config()->set('security-defense.detection.rules.path_reconnaissance.threshold', 2);
        config()->set('security-defense.detection.rules.path_reconnaissance.window', 60);

        $rule = app(PathReconnaissanceRule::class);
        $ip = '185.220.101.5';

        $rule->evaluate(new SecurityEvent(ip: $ip, identifier: 'g', eventType: 'HttpRequestTelemetry', metadata: ['path' => '.env']));
        $threat = $rule->evaluate(new SecurityEvent(ip: $ip, identifier: 'g', eventType: 'HttpRequestTelemetry', metadata: ['path' => 'wp-login.php']));

        $this->assertNotNull($threat);
        $this->assertEquals(2, $threat->metadata['probe_count']);
    }

    public function test_rate_limit_bypass_atomic_counter(): void
    {
        config()->set('security-defense.detection.rules.rate_limit_bypass.threshold', 2);
        config()->set('security-defense.detection.rules.rate_limit_bypass.window', 60);

        $rule = app(RateLimitBypassRule::class);
        $ip = '1.2.3.4';

        $rule->evaluate(new SecurityEvent(ip: $ip, identifier: 'g', eventType: 'HttpRequestTelemetry', userAgent: 'Mozilla'));
        $threat = $rule->evaluate(new SecurityEvent(ip: $ip, identifier: 'g', eventType: 'HttpRequestTelemetry', userAgent: 'Mozilla'));

        $this->assertNotNull($threat);
        $this->assertGreaterThanOrEqual(2, $threat->metadata['distinct_cycled_ips']);
    }
}
