<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Queue;
use Mixudev\SecurityDefense\Events\IpQuarantined;
use Mixudev\SecurityDefense\Events\SecurityParameterTampered;
use Mixudev\SecurityDefense\Events\SecuritySessionCompromised;
use Mixudev\SecurityDefense\Jobs\ProcessSecurityDataAuditJob;
use Mixudev\SecurityDefense\Services\DataAuditService;
use Mixudev\SecurityDefense\Services\IpQuarantineService;
use Mixudev\SecurityDefense\Tests\TestCase;

class AsyncQueueAndSecurityEventsTest extends TestCase
{
    public function test_audit_mutation_pushes_to_queue_when_configured(): void
    {
        Queue::fake();
        config(['security-defense.data_audit.queue.enabled' => true]);

        $model = new class extends \Illuminate\Database\Eloquent\Model {
            protected $guarded = [];
            protected $table = 'test_users';
        };
        $model->id = 1;
        $model->name = 'Alice';

        $service = $this->app->make(DataAuditService::class);
        $result = $service->recordMutation($model, 'created');

        $this->assertNull($result);
        Queue::assertPushed(ProcessSecurityDataAuditJob::class);
    }

    public function test_ip_quarantine_dispatches_ip_quarantined_event(): void
    {
        Event::fake([IpQuarantined::class]);

        $service = $this->app->make(IpQuarantineService::class);
        $service->jail('203.0.113.199', 600, 'Test violation');

        Event::assertDispatched(IpQuarantined::class, function ($event) {
            return $event->ip === '203.0.113.199' && $event->duration === 600;
        });
    }
}
