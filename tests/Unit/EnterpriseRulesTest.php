<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\Rules\PathReconnaissanceRule;
use Mixudev\SecurityDefense\Rules\UserAgentAnomalyRule;
use Mixudev\SecurityDefense\Tests\TestCase;

class EnterpriseRulesTest extends TestCase
{
    public function test_path_reconnaissance_rule_detects_probing_sensitive_files(): void
    {
        config()->set('security-defense.detection.rules.path_reconnaissance.threshold', 2);
        config()->set('security-defense.detection.rules.path_reconnaissance.window', 60);

        $rule = app(PathReconnaissanceRule::class);
        $attackerIp = '185.220.101.5';

        // Probe 1: .env file
        $event1 = new SecurityEvent(
            ip: $attackerIp,
            identifier: 'guest',
            eventType: 'HttpRequestTelemetry',
            metadata: ['path' => '.env']
        );
        $this->assertNull($rule->evaluate($event1));

        // Probe 2: .git/config -> reaches threshold
        $event2 = new SecurityEvent(
            ip: $attackerIp,
            identifier: 'guest',
            eventType: 'HttpRequestTelemetry',
            metadata: ['path' => '.git/config']
        );
        $threat = $rule->evaluate($event2);

        $this->assertNotNull($threat);
        $this->assertEquals('path_reconnaissance', $threat->threatType);
        $this->assertEquals($attackerIp, $threat->metadata['ip']);
        $this->assertEquals(2, $threat->metadata['probe_count']);
    }

    public function test_user_agent_anomaly_rule_detects_known_scanners(): void
    {
        $rule = app(UserAgentAnomalyRule::class);

        $scanners = [
            'sqlmap/1.6.5#stable' => 'sqlmap',
            'Mozilla/5.0 (compatible; Nikto/2.1.6)' => 'nikto',
            'DirBuster-1.0-RC1' => 'dirbuster',
            'gobuster/3.1.0' => 'gobuster',
            'WPScan v3.8.22' => 'wpscan',
        ];

        foreach ($scanners as $ua => $expectedTool) {
            $event = new SecurityEvent(
                ip: '103.21.244.2',
                identifier: 'guest',
                eventType: 'HttpRequestTelemetry',
                userAgent: $ua
            );

            $threat = $rule->evaluate($event);
            $this->assertNotNull($threat, "Failed detecting scanner: {$expectedTool}");
            $this->assertEquals('user_agent_anomaly', $threat->threatType);
            $this->assertEquals($expectedTool, $threat->metadata['detected_tool']);
        }
    }

    public function test_user_agent_anomaly_rule_ignores_legitimate_browsers(): void
    {
        $rule = app(UserAgentAnomalyRule::class);

        $legitimateBrowsers = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        ];

        foreach ($legitimateBrowsers as $ua) {
            $event = new SecurityEvent(
                ip: '127.0.0.1',
                identifier: 'john',
                eventType: 'HttpRequestTelemetry',
                userAgent: $ua
            );

            $this->assertNull($rule->evaluate($event));
        }
    }
}
