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

class AlertDispatcher
{
    /** @var array<string, AlertChannel> */
    protected array $channels = [];

    public function __construct(
        protected AlertDeduplicatorInterface $deduplicator,
        iterable $channels = []
    ) {
        foreach ($channels as $channel) {
            $this->registerChannel($channel);
        }
    }

    public function registerChannel(AlertChannel $channel): self
    {
        $this->channels[$channel->identifier()] = $channel;

        return $this;
    }

    /** @return array<string, AlertChannel> */
    public function getChannels(): array
    {
        return $this->channels;
    }

    public function dispatch(SecurityThreat $threat): ?SecurityAlert
    {
        if (!$this->deduplicator->shouldAlert($threat)) {
            return null;
        }

        if (!$this->acquireRateLimitSlot()) {
            $this->deduplicator->forget($threat->fingerprint);
            return null;
        }

        $metadata = $this->boundMetadata(
            $threat->metadata,
            max(1, (int) config('security-defense.hardening.max_alert_metadata_size', 16384))
        );

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

        $useQueue = (bool) config('security-defense.alerts.queue.enabled', false);
        foreach ($this->channels as $identifier => $channel) {
            if ($identifier === 'database' || !$channel->isEnabled() || !$channel->isConfigured()) {
                continue;
            }
            if ($useQueue) {
                dispatch(new DispatchAlertChannelJob(get_class($channel), $alert));
            } else {
                $channel->send($alert);
            }
        }

        event(new SecurityAlertCreated($alert, $threat));

        return $alert;
    }

    public function resolveAlert(SecurityAlert $alert): bool
    {
        $alert->resolve();
        event(new SecurityAlertResolved($alert));

        return true;
    }

    /** Atomically reserve one slot. Never allows more than cap. */
    protected function acquireRateLimitSlot(): bool
    {
        if (!(bool) config('security-defense.hardening.alert_rate_limit.enabled', true)) {
            return true;
        }

        $max = max(0, (int) config('security-defense.hardening.alert_rate_limit.max_alerts_per_minute', 60));
        $key = config('security-defense.cache_prefix', 'security_defense:') . 'rate_limit:alerts_per_minute';
        $cache = Cache::store(config('security-defense.cache_store'));

        $reserve = function () use ($cache, $key, $max): bool {
            $cache->add($key, 0, 60);
            $current = (int) $cache->increment($key);
            if ($current <= $max) {
                return true;
            }
            $cache->decrement($key);
            return false;
        };

        if (method_exists($cache, 'lock')) {
            return (bool) $cache->lock($key . ':lock', 5)->block(1, $reserve);
        }

        return $reserve();

    }

    /** Recursively trim strings first, then enforce one global JSON byte ceiling. */
    protected function boundMetadata(array $metadata, int $maxBytes): array
    {
        $originalJson = (string) json_encode($metadata);

        $trim = function (mixed $value) use (&$trim): mixed {
            if (is_array($value)) {
                $result = [];
                foreach ($value as $key => $child) {
                    $result[$key] = $trim($child);
                }
                return $result;
            }
            if (is_string($value) && strlen($value) > 200) {
                return substr($value, 0, 200) . '...[TRUNCATED]';
            }
            return $value;
        };

        $bounded = $trim($metadata);
        $bytes = strlen((string) json_encode($bounded));

        if ($bytes <= $maxBytes) {
            return $bounded;
        }

        // If still too large after trimming strings, drop keys from the end.
        $dropped = ($bounded !== $metadata);
        while ($bytes > $maxBytes && $bounded !== []) {
            $key = array_key_last($bounded);
            unset($bounded[$key]);
            $bytes = strlen((string) json_encode($bounded));
            $dropped = true;
        }

        if ($dropped && $bytes <= $maxBytes) {
            $bounded['_truncated'] = true;
            if (strlen((string) json_encode($bounded)) > $maxBytes && count($bounded) > 1) {
                // The marker itself didn't fit, drop it.
                unset($bounded['_truncated']);
            }
        }

        return $bounded;
    }
}
