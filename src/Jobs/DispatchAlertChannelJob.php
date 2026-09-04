<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Mixudev\SecurityDefense\Contracts\AlertChannel;
use Mixudev\SecurityDefense\Models\SecurityAlert;

/**
 * Background queue job for delivering security alerts asynchronously across channels.
 */
class DispatchAlertChannelJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    /**
     * @param string $channelClass
     * @param SecurityAlert $alert
     */
    public function __construct(
        public readonly string $channelClass,
        public readonly SecurityAlert $alert
    ) {
        $connection = config('security-defense.alerts.queue.connection');
        if ($connection) {
            $this->onConnection((string) $connection);
        }

        $queueName = config('security-defense.alerts.queue.queue_name');
        if ($queueName) {
            $this->onQueue((string) $queueName);
        }
    }

    /**
     * Execute the job.
     */
    public function handle(): void
    {
        /** @var AlertChannel $channel */
        $channel = app($this->channelClass);

        if ($channel->isEnabled() && $channel->isConfigured()) {
            $channel->send($this->alert);
        }
    }
}
