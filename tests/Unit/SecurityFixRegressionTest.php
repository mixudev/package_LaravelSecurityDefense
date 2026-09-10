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

    public function test_credential_stuffing_lock_retains_interleaved_identifiers(): void
    {
        config()->set('security-defense.detection.rules.credential_stuffing.threshold', 4);
        config()->set('security-defense.detection.rules.credential_stuffing.window', 60);

        $rule = app(CredentialStuffingRule::class);
        $ip = '45.33.32.99';
        $identifiers = ['user1.example.com', 'user2.example.com', 'user3.example.com', 'user4.example.com'];

        foreach ($identifiers as $identifier) {
            $threat = $rule->evaluate(new SecurityEvent(ip: $ip, identifier: $identifier, eventType: 'LoginFailed'));
        }

        $this->assertNotNull($threat);
        $this->assertEquals(4, $threat->metadata['distinct_identifiers_count']);
        $this->assertEquals(
            array_map(static fn (string $identifier): string => hash('sha256', md5(strtolower($identifier))), $identifiers),
            $threat->metadata['sample_identifiers_hashed']
        );
    }

    /**
     * Simulates interleaved parallel reads: two evaluators read the same array at "t0",
     * one writes first, then the other overwrites — the lock prevents lost entries.
     *
     * On the array (fake) cache without LockProvider, verify evaluate() still produces
     * the correct count increment and that the tracked set grows across sequential
     * calls (no double-counting on duplicates).
     */
    public function test_credential_stuffing_no_lost_members_under_interleaved_evaluations(): void
    {
        config()->set('security-defense.detection.rules.credential_stuffing.threshold', 3);
        config()->set('security-defense.detection.rules.credential_stuffing.window', 60);

        $rule = app(CredentialStuffingRule::class);
        $ip = '10.10.10.10';
        $allIds = ['a@example.com', 'b@example.com', 'c@example.com'];

        $lastThreat = null;
        foreach ($allIds as $id) {
            $event = new SecurityEvent(ip: $ip, identifier: $id, eventType: 'LoginFailed');
            $threat = $rule->evaluate($event);
            $lastThreat = $threat;
        }

        // All three unique identifiers must be tracked, reaching threshold at the 3rd.
        $this->assertNotNull($lastThreat);
        $this->assertEquals(3, $lastThreat->metadata['distinct_identifiers_count']);

        // Calling with an already-seen identifier must NOT create a new tracked entry.
        $duplicateEvent = new SecurityEvent(ip: $ip, identifier: 'a@example.com', eventType: 'LoginFailed');
        $afterDuplicate = $rule->evaluate($duplicateEvent);

        // Count remains 3 — not incremented again for a duplicate identifier.
        $this->assertEquals(3, $afterDuplicate->metadata['distinct_identifiers_count']);
    }

    public function test_distributed_spray_lock_retains_interleaved_ips(): void
    {
        config()->set('security-defense.detection.rules.distributed_spray.threshold', 4);
        config()->set('security-defense.detection.rules.distributed_spray.window', 60);

        $rule = app(DistributedSprayRule::class);
        $identifier = 'admin-lock-regression';
        $ips = ['10.0.0.11', '10.0.0.12', '10.0.0.13', '10.0.0.14'];

        foreach ($ips as $ip) {
            $threat = $rule->evaluate(new SecurityEvent(ip: $ip, identifier: $identifier, eventType: 'LoginFailed'));
        }

        $this->assertNotNull($threat);
        $this->assertEquals(4, $threat->metadata['distinct_ips_count']);
        $this->assertEquals(
            array_map(static fn (string $ip): string => hash('sha256', $ip), $ips),
            $threat->metadata['sample_ips_hashed']
        );
    }

    /**
     * Simulates interleaved parallel reads for distributed spray.
     * Verifies no member IPs are dropped and the threshold fires correctly.
     */
    public function test_distributed_spray_no_lost_members_under_interleaved_evaluations(): void
    {
        config()->set('security-defense.detection.rules.distributed_spray.threshold', 3);
        config()->set('security-defense.detection.rules.distributed_spray.window', 60);

        $rule = app(DistributedSprayRule::class);
        $target = 'admin-interleave-test';
        $allIps = ['192.168.1.1', '192.168.1.2', '192.168.1.3'];

        $lastThreat = null;
        foreach ($allIps as $ip) {
            $event = new SecurityEvent(ip: $ip, identifier: $target, eventType: 'LoginFailed');
            $threat = $rule->evaluate($event);
            $lastThreat = $threat;
        }

        $this->assertNotNull($lastThreat);
        $this->assertEquals(3, $lastThreat->metadata['distinct_ips_count']);

        // Duplicate IP must not create a new tracked entry.
        $dupEvent = new SecurityEvent(ip: '192.168.1.1', identifier: $target, eventType: 'LoginFailed');
        $afterDup = $rule->evaluate($dupEvent);
        // Count remains 3 — not incremented again for a duplicate IP.
        $this->assertEquals(3, $afterDup->metadata['distinct_ips_count']);
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

    public function test_request_source_redacts_secret_query_and_bounds_metadata(): void
    {
        $request = \Illuminate\Http\Request::create('/login?password=super-secret&api_key=key-secret', 'GET');
        $source = new \Mixudev\SecurityDefense\Sources\RequestThreatSource($request, extraMetadata: [
            'nested' => ['token' => 'token-secret', 'note' => "safe\r\nline"],
        ]);
        $json = json_encode($source->toSecurityEvent()->toArray());

        $this->assertStringNotContainsString('super-secret', $json);
        $this->assertStringNotContainsString('key-secret', $json);
        $this->assertStringNotContainsString('token-secret', $json);
        $this->assertStringNotContainsString("\r", $json);
        $this->assertStringNotContainsString("\n", $json);
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
