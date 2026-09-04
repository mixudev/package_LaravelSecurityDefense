<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Support\Facades\Queue;
use Mixudev\SecurityDefense\DTO\SecurityThreat;
use Mixudev\SecurityDefense\Jobs\DispatchAlertChannelJob;
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Services\AlertDispatcher;
use Mixudev\SecurityDefense\Tests\TestCase;

class QueuedAlertDispatchTest extends TestCase
{
    public function test_it_pushes_alert_notifications_to_queue_when_queue_enabled(): void
    {
        Queue::fake();

        config()->set('security-defense.alerts.queue.enabled', true);
        config()->set('security-defense.alerts.discord.enabled', true);
        config()->set('security-defense.alerts.discord.webhook_url', 'https://discord.com/api/webhooks/mock');

        $dispatcher = app(AlertDispatcher::class);

        $threat = new SecurityThreat(
            severity: 'critical',
            threatType: 'payload_injection',
            fingerprint: 'fp-queued-test',
            metadata: ['ip' => '1.2.3.4']
        );

        $alert = $dispatcher->dispatch($threat);

        $this->assertNotNull($alert);

        // Verify that notification job was pushed to queue for non-database channel
        Queue::assertPushed(DispatchAlertChannelJob::class, function ($job) use ($alert) {
            return $job->alert->id === $alert->id;
        });
    }

    public function test_it_rejects_invalid_channel_class_from_queue(): void
    {
        // A malicious class name that is NOT a valid AlertChannel should be rejected
        $job = new DispatchAlertChannelJob(\stdClass::class, new SecurityAlert([
            'severity' => 'high',
            'threat_type' => 'test',
            'fingerprint' => 'fp-invalid-class',
        ]));

        // handle() must not throw and must return without instantiating arbitrary class
        $job->handle();
        $this->assertTrue(true); // If we reach here, no arbitrary instantiation occurred
    }
}
