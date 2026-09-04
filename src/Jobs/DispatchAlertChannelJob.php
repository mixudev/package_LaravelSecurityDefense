<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Mixudev\SecurityDefense\Channels\DatabaseChannel;
use Mixudev\SecurityDefense\Channels\DiscordChannel;
use Mixudev\SecurityDefense\Channels\MailChannel;
use Mixudev\SecurityDefense\Channels\TelegramChannel;
use Mixudev\SecurityDefense\Channels\WebhookChannel;
use Mixudev\SecurityDefense\Contracts\AlertChannel;
use Mixudev\SecurityDefense\Models\SecurityAlert;

/**
 * Background queue job for delivering security alerts asynchronously across channels.
 * Whitelist prevents arbitrary class instantiation from queue payload.
 */
class DispatchAlertChannelJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    /**
     * Whitelist of valid channel classes that can be instantiated from queue.
     *
     * @var array<int, class-string<AlertChannel>>
     */
    private const VALID_CHANNELS = [
        DatabaseChannel::class,
        TelegramChannel::class,
        DiscordChannel::class,
        WebhookChannel::class,
        MailChannel::class,
    ];

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
        if (!in_array($this->channelClass, self::VALID_CHANNELS, true)) {
            \Illuminate\Support\Facades\Log::error('SecurityDefense: Invalid channel class rejected in queue job.', [
                'channel' => $this->channelClass,
            ]);
            return;
        }

        /** @var AlertChannel $channel */
        $channel = app($this->channelClass);

        if ($channel->isEnabled() && $channel->isConfigured()) {
            $channel->send($this->alert);
        }
    }
}
