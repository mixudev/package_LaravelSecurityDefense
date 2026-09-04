<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Support\Facades\Event;
use Mixudev\SecurityDefense\Events\SecurityAlertCreated;
use Mixudev\SecurityDefense\Events\SecurityAlertResolved;
use Mixudev\SecurityDefense\Events\ThreatDetected;
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Sources\GenericArraySource;
use Mixudev\SecurityDefense\Support\Facades\SecurityDefense;
use Mixudev\SecurityDefense\Tests\TestCase;

class SecurityDefenseEndToEndTest extends TestCase
{
    public function test_full_detection_and_alerting_workflow(): void
    {
        Event::fake([
            ThreatDetected::class,
            SecurityAlertCreated::class,
            SecurityAlertResolved::class,
        ]);

        config()->set('security-defense.detection.rules.brute_force.threshold', 2);
        config()->set('security-defense.detection.rules.brute_force.window', 60);

        // Feed event 1
        SecurityDefense::record([
            'ip' => '203.0.113.195',
            'identifier' => 'target.user@app.test',
            'eventType' => 'LoginFailed',
            'metadata' => [
                'password' => 'attempt1',
            ],
        ]);

        // No threat yet
        Event::assertNotDispatched(ThreatDetected::class);

        // Feed event 2 -> Triggers brute force threshold
        $threats = SecurityDefense::record(new GenericArraySource([
            'ip' => '203.0.113.195',
            'identifier' => 'target.user@app.test',
            'eventType' => 'LoginFailed',
            'metadata' => [
                'password' => 'attempt2',
            ],
        ]));

        $this->assertCount(1, $threats);
        $this->assertEquals('brute_force', $threats[0]->threatType);

        // Domain events dispatched
        Event::assertDispatched(ThreatDetected::class);
        Event::assertDispatched(SecurityAlertCreated::class);

        // Check database persistence
        /** @var SecurityAlert $alert */
        $alert = SecurityAlert::query()->where('threat_type', 'brute_force')->firstOrFail();
        $this->assertEquals(SecurityAlert::STATUS_NEW, $alert->status);
        $this->assertEquals('target.user@app.test', $alert->metadata['target']);
        $this->assertArrayNotHasKey('password', $alert->metadata); // Verified sanitized!

        // Test resolving the alert
        SecurityDefense::resolveAlert($alert);

        $alert->refresh();
        $this->assertEquals(SecurityAlert::STATUS_RESOLVED, $alert->status);
        $this->assertNotNull($alert->resolved_at);
        Event::assertDispatched(SecurityAlertResolved::class);
    }

    public function test_alert_metadata_is_truncated_when_oversized(): void
    {
        Event::fake([ThreatDetected::class, SecurityAlertCreated::class, SecurityAlertResolved::class]);

        config()->set('security-defense.hardening.max_alert_metadata_size', 256);

        $dispatcher = app(\Mixudev\SecurityDefense\Services\AlertDispatcher::class);

        // Threat with an oversized metadata blob
        $threat = new \Mixudev\SecurityDefense\DTO\SecurityThreat(
            severity: 'high',
            threatType: 'brute_force',
            fingerprint: 'fp-oversized',
            metadata: ['target' => 'admin', 'big_blob' => str_repeat('A', 5000)],
            ruleIdentifier: 'brute_force'
        );

        $alert = $dispatcher->dispatch($threat);
        $this->assertNotNull($alert);

        $metadataJson = json_encode($alert->metadata);
        $this->assertLessThanOrEqual(1024, strlen((string) $metadataJson), 'Metadata must be bounded');
        // Truncation marker OR truncated value should appear
        $this->assertTrue(
            (isset($alert->metadata['_truncated']) && $alert->metadata['_truncated'])
            || str_contains((string) $metadataJson, '[TRUNCATED]'),
            'Oversized metadata must be bounded'
        );
    }

    public function test_payload_injection_strips_control_characters_from_sample(): void
    {
        $rule = app(\Mixudev\SecurityDefense\Rules\PayloadInjectionRule::class);

        // SQLi payload with embedded control characters (newline/carriage return)
        $event = new \Mixudev\SecurityDefense\DTO\SecurityEvent(
            ip: '198.51.100.10',
            identifier: 'guest',
            eventType: 'HttpRequestTelemetry',
            metadata: [
                'query' => ['q' => "' OR 1=1--\n\x00DROP"],
            ]
        );

        $threat = $rule->evaluate($event);
        $this->assertNotNull($threat);
        // Control characters must be stripped from stored sample
        $this->assertStringNotContainsString("\n", $threat->metadata['matched_signature']);
        $this->assertStringNotContainsString("\x00", $threat->metadata['matched_signature']);
    }
}
