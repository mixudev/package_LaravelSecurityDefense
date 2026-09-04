<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\Rules\BruteForceRule;
use Mixudev\SecurityDefense\Rules\CredentialStuffingRule;
use Mixudev\SecurityDefense\Rules\DistributedSprayRule;
use Mixudev\SecurityDefense\Rules\ImpossibleTravelRule;
use Mixudev\SecurityDefense\Rules\PayloadInjectionRule;
use Mixudev\SecurityDefense\Rules\RateLimitBypassRule;
use Mixudev\SecurityDefense\Tests\TestCase;

class DetectionRulesTest extends TestCase
{
    public function test_brute_force_rule_detects_repeated_failed_attempts(): void
    {
        config()->set('security-defense.detection.rules.brute_force.threshold', 3);
        config()->set('security-defense.detection.rules.brute_force.window', 60);

        $rule = app(BruteForceRule::class);

        $event = new SecurityEvent(
            ip: '192.168.1.100',
            identifier: 'victim@example.com',
            eventType: 'LoginFailed'
        );

        $this->assertNull($rule->evaluate($event)); // attempt 1
        $this->assertNull($rule->evaluate($event)); // attempt 2

        $threat = $rule->evaluate($event); // attempt 3 -> threshold reached!
        $this->assertNotNull($threat);
        $this->assertEquals('brute_force', $threat->threatType);
        $this->assertEquals('victim@example.com', $threat->metadata['target']);
        $this->assertEquals(3, $threat->metadata['attempt_count']);
    }

    public function test_credential_stuffing_rule_detects_multiple_accounts_from_one_ip(): void
    {
        config()->set('security-defense.detection.rules.credential_stuffing.threshold', 3);
        config()->set('security-defense.detection.rules.credential_stuffing.window', 60);

        $rule = app(CredentialStuffingRule::class);

        $rule->evaluate(new SecurityEvent(ip: '45.33.32.1', identifier: 'user1', eventType: 'LoginFailed'));
        $rule->evaluate(new SecurityEvent(ip: '45.33.32.1', identifier: 'user2', eventType: 'LoginFailed'));

        $threat = $rule->evaluate(new SecurityEvent(ip: '45.33.32.1', identifier: 'user3', eventType: 'LoginFailed'));

        $this->assertNotNull($threat);
        $this->assertEquals('credential_stuffing', $threat->threatType);
        $this->assertEquals('45.33.32.1', $threat->metadata['ip']);
        $this->assertEquals(3, $threat->metadata['distinct_identifiers_count']);
    }

    public function test_distributed_spray_rule_detects_multiple_ips_targeting_single_account(): void
    {
        config()->set('security-defense.detection.rules.distributed_spray.threshold', 3);
        config()->set('security-defense.detection.rules.distributed_spray.window', 60);

        $rule = app(DistributedSprayRule::class);

        $rule->evaluate(new SecurityEvent(ip: '10.0.0.1', identifier: 'admin', eventType: 'LoginFailed'));
        $rule->evaluate(new SecurityEvent(ip: '10.0.0.2', identifier: 'admin', eventType: 'LoginFailed'));

        $threat = $rule->evaluate(new SecurityEvent(ip: '10.0.0.3', identifier: 'admin', eventType: 'LoginFailed'));

        $this->assertNotNull($threat);
        $this->assertEquals('distributed_spray', $threat->threatType);
        $this->assertEquals('admin', $threat->metadata['identifier']);
        $this->assertEquals(3, $threat->metadata['distinct_ips_count']);
    }

    public function test_rate_limit_bypass_rule_detects_proxy_spoofing(): void
    {
        $rule = app(RateLimitBypassRule::class);

        $event = new SecurityEvent(
            ip: '1.2.3.4',
            identifier: 'guest',
            eventType: 'HttpRequestTelemetry',
            metadata: [
                'headers' => [
                    'x-forwarded-for' => '1.1.1.1, 2.2.2.2, 3.3.3.3, 4.4.4.4, 5.5.5.5, 6.6.6.6',
                ],
            ]
        );

        $threat = $rule->evaluate($event);
        $this->assertNotNull($threat);
        $this->assertEquals('rate_limit_bypass', $threat->threatType);
        $this->assertTrue($threat->metadata['spoof_detected']);
    }

    public function test_payload_injection_rule_detects_sqli_and_xss(): void
    {
        $rule = app(PayloadInjectionRule::class);

        // SQLi payload test
        $sqliEvent = new SecurityEvent(
            ip: '198.51.100.1',
            identifier: 'guest',
            eventType: 'HttpRequestTelemetry',
            metadata: [
                'query' => ['q' => "1' UNION SELECT username, password FROM users--"],
            ]
        );

        $sqliThreat = $rule->evaluate($sqliEvent);
        $this->assertNotNull($sqliThreat);
        $this->assertEquals('payload_injection', $sqliThreat->threatType);
        $this->assertEquals('sqli', $sqliThreat->metadata['category']);

        // XSS payload test
        $xssEvent = new SecurityEvent(
            ip: '198.51.100.2',
            identifier: 'guest',
            eventType: 'HttpRequestTelemetry',
            metadata: [
                'input' => ['comment' => '<script>alert(document.cookie)</script>'],
            ]
        );

        $xssThreat = $rule->evaluate($xssEvent);
        $this->assertNotNull($xssThreat);
        $this->assertEquals('payload_injection', $xssThreat->threatType);
        $this->assertEquals('xss', $xssThreat->metadata['category']);
    }

    public function test_impossible_travel_rule_detects_excessive_speed(): void
    {
        $rule = app(ImpossibleTravelRule::class);

        // Step 1: Login from Jakarta (-6.2088, 106.8456)
        $rule->evaluate(new SecurityEvent(
            ip: '180.252.1.1',
            identifier: 'traveler@company.com',
            eventType: 'LoginSucceeded',
            metadata: [
                'latitude' => -6.2088,
                'longitude' => 106.8456,
            ]
        ));

        // Step 2: Login from London (51.5074, -0.1278) just 1 second later (distance ~11,700 km)
        $threat = $rule->evaluate(new SecurityEvent(
            ip: '81.2.69.142',
            identifier: 'traveler@company.com',
            eventType: 'LoginSucceeded',
            metadata: [
                'latitude' => 51.5074,
                'longitude' => -0.1278,
            ]
        ));

        $this->assertNotNull($threat);
        $this->assertEquals('impossible_travel', $threat->threatType);
        $this->assertGreaterThan(900.0, $threat->metadata['calculated_speed_kmh']);
    }
}
