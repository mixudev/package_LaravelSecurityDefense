<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Services;

use Illuminate\Support\Facades\Cache;
use Mixudev\SecurityDefense\Contracts\AlertChannel;
use Mixudev\SecurityDefense\Contracts\AlertDeduplicatorInterface;
use Mixudev\SecurityDefense\DTO\SecurityThreat;
use Mixudev\SecurityDefense\Events\SecurityAlertCreated;
use Mixudev\SecurityDefense\Events\SecurityAlertResolved;
use Mixudev\SecurityDefense\Jobs\DispatchAlertChannelJob;
use Mixudev\SecurityDefense\Models\SecurityAlert;

/**
 * Orchestrates alert deduplication, rate limiting, database persistence, and channel broadcasting.
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
     * Process a detected threat: rate limit, deduplicate, persist, notify channels, and emit domain event.
     *
     * @param SecurityThreat $threat
     * @return SecurityAlert|null Returns created SecurityAlert, or null if suppressed.
     */
    public function dispatch(SecurityThreat $threat): ?SecurityAlert
    {
        // 1. Check global alert rate limit (Anti-Disk Exhaustion Hardening)
        if ($this->isRateLimited()) {
            return null;
        }

        // 2. Deduplication evaluation
        if (!$this->deduplicator->shouldAlert($threat)) {
            return null;
        }

        // 3. Record fingerprint in deduplicator cache window
        $this->deduplicator->record($threat);

        // 4. Truncate metadata if too large (prevent storage exhaustion)
        $maxMetadataSize = (int) config('security-defense.hardening.max_alert_metadata_size', 16384);
        $metadata = $threat->metadata;
        $metadataJson = json_encode($metadata);
        if (strlen((string) $metadataJson) > $maxMetadataSize) {
            // Trim oversized string values first, then bound the top-level array size
            $trimmed = [];
            foreach ($metadata as $key => $value) {
                if (is_string($value) && strlen($value) > 200) {
                    $trimmed[$key] = substr($value, 0, 200) . '...[TRUNCATED]';
                } else {
                    $trimmed[$key] = $value;
                }
            }
            // If still too many keys, keep only the first 10
            if (count($trimmed) > 10) {
                $trimmed = array_slice($trimmed, 0, 10, true);
            }
            $trimmed['_truncated'] = true;
            $trimmed['_original_size'] = strlen((string) $metadataJson);
            $metadata = $trimmed;
        }

        // 5. Persist alert to database (Mandatory default)
        $alert = new SecurityAlert([
            'severity' => $threat->severity,
            'threat_type' => $threat->threatType,
            'fingerprint' => $threat->fingerprint,
            'status' => SecurityAlert::STATUS_NEW,
            'rule_identifier' => $threat->ruleIdentifier,
            'metadata' => $metadata,
        ]);

        $databaseChannel = $this->channels['database'] ?? null;
        if ($databaseChannel !== null && $databaseChannel->isEnabled()) {
            $databaseChannel->send($alert);
        } else {
            $alert->save();
        }

        // 5. Increment rate limiter counter
        $this->incrementRateLimiter();

        // 6. Broadcast to other active channels (Telegram, Discord, Webhook)
        $useQueue = (bool) config('security-defense.alerts.queue.enabled', false);

        foreach ($this->channels as $identifier => $channel) {
            if ($identifier === 'database') {
                continue;
            }

            if (!$channel->isEnabled() || !$channel->isConfigured()) {
                continue;
            }

            if ($useQueue) {
                dispatch(new DispatchAlertChannelJob(get_class($channel), $alert));
            } else {
                $channel->send($alert);
            }
        }

        // 7. Dispatch domain event
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

    /**
     * Check if alert dispatching is currently rate-limited.
     */
    protected function isRateLimited(): bool
    {
        $enabled = (bool) config('security-defense.hardening.alert_rate_limit.enabled', true);
        if (!$enabled) {
            return false;
        }

        $max = (int) config('security-defense.hardening.alert_rate_limit.max_alerts_per_minute', 60);
        $key = config('security-defense.cache_prefix', 'security_defense:') . 'rate_limit:alerts_per_minute';

        $current = (int) Cache::get($key, 0);

        return $current >= $max;
    }

    /**
     * Increment the alert rate limit counter.
     */
    protected function incrementRateLimiter(): void
    {
        $enabled = (bool) config('security-defense.hardening.alert_rate_limit.enabled', true);
        if (!$enabled) {
            return;
        }

        $key = config('security-defense.cache_prefix', 'security_defense:') . 'rate_limit:alerts_per_minute';
        // Atomic: seed TTL only on first create, always increment
        if (!Cache::has($key)) {
            Cache::put($key, 0, 60);
        }
        Cache::increment($key);
    }
}
