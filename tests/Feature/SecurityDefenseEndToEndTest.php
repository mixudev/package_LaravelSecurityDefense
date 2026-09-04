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
}
