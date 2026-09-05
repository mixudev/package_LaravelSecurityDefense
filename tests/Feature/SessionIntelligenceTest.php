<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\Rules\BehavioralVelocityRule;
use Mixudev\SecurityDefense\Rules\HttpHeaderConsistencyRule;
use Mixudev\SecurityDefense\Rules\SessionFingerprintRule;
use Mixudev\SecurityDefense\Tests\TestCase;

class SessionIntelligenceTest extends TestCase
{
    public function test_session_fingerprint_rule_detects_hijacking_drift(): void
    {
        $rule = app(SessionFingerprintRule::class);

        $event1 = new SecurityEvent(
            ip: '203.0.113.10',
            identifier: 'user_42',
            eventType: 'AuthenticatedRequest',
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
            metadata: ['session_id' => 'sess_test_123456']
        );

        // First request establishes baseline
        $threat1 = $rule->evaluate($event1);
        $this->assertNull($threat1);

        // Same session replayed from completely different subnet and curl UA (stolen cookie)
        $event2 = new SecurityEvent(
            ip: '198.51.100.99',
            identifier: 'user_42',
            eventType: 'AuthenticatedRequest',
            userAgent: 'curl/7.88.1',
            metadata: ['session_id' => 'sess_test_123456']
        );

        $threat2 = $rule->evaluate($event2);
        $this->assertNotNull($threat2);
        $this->assertSame('session_hijack_suspected', $threat2->threatType);
        $this->assertSame('critical', $threat2->severity);
        $this->assertContains('user_agent_drift', $threat2->metadata['mismatches']);
        $this->assertContains('network_subnet_drift', $threat2->metadata['mismatches']);
    }

    public function test_behavioral_velocity_rule_flags_high_rpm(): void
    {
        $rule = app(BehavioralVelocityRule::class);
        $userId = 'victim_admin_99';

        for ($i = 0; $i < 119; $i++) {
            $event = new SecurityEvent(
                ip: '192.168.1.50',
                identifier: $userId,
                eventType: 'AuthenticatedRequest'
            );
            $rule->evaluate($event);
        }

        // 120th request hits the threshold
        $event120 = new SecurityEvent(
            ip: '192.168.1.50',
            identifier: $userId,
            eventType: 'AuthenticatedRequest'
        );

        $threat = $rule->evaluate($event120);
        $this->assertNotNull($threat);
        $this->assertSame('suspicious_velocity_scraping', $threat->threatType);
        $this->assertSame(120, $threat->metadata['requests_in_window']);
    }

    public function test_header_consistency_rule_detects_headless_bot(): void
    {
        $rule = app(HttpHeaderConsistencyRule::class);

        // Claiming Chrome User-Agent, but missing Accept-Language and Sec-Fetch headers
        $event = new SecurityEvent(
            ip: '192.168.1.88',
            identifier: 'anonymous',
            eventType: 'WebRequest',
            userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            metadata: [
                'headers' => [
                    'host' => 'example.com',
                    'user-agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                ]
            ]
        );

        $threat = $rule->evaluate($event);
        $this->assertNotNull($threat);
        $this->assertSame('header_inconsistency_bot', $threat->threatType);
        $this->assertContains('browser_ua_without_accept_language', $threat->metadata['anomalies']);
    }
}
