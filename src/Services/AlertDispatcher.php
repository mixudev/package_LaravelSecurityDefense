<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Services;

use Mixudev\SecurityDefense\Contracts\AlertChannel;
use Mixudev\SecurityDefense\Contracts\AlertDeduplicatorInterface;
use Mixudev\SecurityDefense\DTO\SecurityThreat;
use Mixudev\SecurityDefense\Events\SecurityAlertCreated;
use Mixudev\SecurityDefense\Events\SecurityAlertResolved;
use Mixudev\SecurityDefense\Models\SecurityAlert;

/**
 * Orchestrates alert deduplication, database persistence, and channel broadcasting.
 */
class AlertDispatcher
{
    /**
     * Registered alert channels.
     *
     * @var array<string, AlertChannel>
     */
    protected array $channels = [];

    /**
     * @param AlertDeduplicatorInterface $deduplicator
     * @param iterable<AlertChannel> $channels
     */
    public function __construct(
        protected AlertDeduplicatorInterface $deduplicator,
        iterable $channels = []
    ) {
        foreach ($channels as $channel) {
            $this->registerChannel($channel);
        }
    }

    /**
     * Register an alert channel.
     */
    public function registerChannel(AlertChannel $channel): self
    {
        $this->channels[$channel->identifier()] = $channel;

        return $this;
    }

    /**
     * Retrieve all registered channels.
     *
     * @return array<string, AlertChannel>
     */
    public function getChannels(): array
    {
        return $this->channels;
    }

    /**
     * Process a detected threat: deduplicate, persist, notify channels, and emit domain event.
     *
     * @param SecurityThreat $threat
     * @return SecurityAlert|null Returns created SecurityAlert, or null if suppressed by deduplication.
     */
    public function dispatch(SecurityThreat $threat): ?SecurityAlert
    {
        // 1. Deduplication evaluation
        if (!$this->deduplicator->shouldAlert($threat)) {
            return null;
        }

        // 2. Record fingerprint in deduplicator cache window
        $this->deduplicator->record($threat);

        // 3. Persist alert to database (Mandatory default)
        $alert = new SecurityAlert([
            'severity' => $threat->severity,
            'threat_type' => $threat->threatType,
            'fingerprint' => $threat->fingerprint,
            'status' => SecurityAlert::STATUS_NEW,
            'rule_identifier' => $threat->ruleIdentifier,
            'metadata' => $threat->metadata,
        ]);

        $databaseChannel = $this->channels['database'] ?? null;
        if ($databaseChannel !== null && $databaseChannel->isEnabled()) {
            $databaseChannel->send($alert);
        } else {
            $alert->save();
        }

        // 4. Broadcast to other active channels (Telegram, Discord, Webhook)
        foreach ($this->channels as $identifier => $channel) {
            if ($identifier === 'database') {
                continue;
            }

            if ($channel->isEnabled() && $channel->isConfigured()) {
                $channel->send($alert);
            }
        }

        // 5. Dispatch domain event
        event(new SecurityAlertCreated($alert, $threat));

        return $alert;
    }

    /**
     * Resolve an alert and dispatch event.
     */
    public function resolveAlert(SecurityAlert $alert): bool
    {
        $alert->resolve();

        event(new SecurityAlertResolved($alert));

        return true;
    }
}
