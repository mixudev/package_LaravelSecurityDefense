<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Rules;

use Illuminate\Contracts\Cache\LockProvider;
use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\DTO\SecurityThreat;
/**
 * Detects distributed spray attacks where multiple distinct IPs probe the same account identifier.
 * Atomic counter eliminates race condition on parallel requests.
 * IP addresses are hashed in metadata to prevent information leakage.
 */
class DistributedSprayRule extends AbstractDetectionRule
{
    public function identifier(): string
    {
        return 'distributed_spray';
    }

    public function name(): string
    {
        return 'Distributed Password Spray Detector';
    }

    public function evaluate(SecurityEvent $event): ?SecurityThreat
    {
        if (!$this->isEnabled()) {
            return null;
        }

        $monitoredEvents = (array) $this->getConfig('events', ['LoginFailed']);
        if (!in_array($event->eventType, $monitoredEvents, true)) {
            return null;
        }

        if ($event->identifier === 'anonymous' || trim($event->identifier) === '') {
            return null;
        }

        $threshold = (int) $this->getConfig('threshold', 5);
        $window = (int) $this->getConfig('window', 300);
        $severity = (string) $this->getConfig('severity', 'high');

        $target = strtolower($event->identifier);

        $cache = $this->getCache();
        $counterKey = $this->getCacheKey('ds_count:' . md5($target));
        $windowKey = $this->getCacheKey('ds_window:' . md5($target));
        $ipTrackingKey = $this->getCacheKey('ds_ips:' . md5($target));

        /** @var array<string, int> $probingIps */
        $probingIps = [];
        $count = 0;
        $update = function () use ($cache, $windowKey, $counterKey, $ipTrackingKey, $window, $event, &$probingIps, &$count): void {
            if (!$cache->has($windowKey)) {
                $cache->put($windowKey, true, $window);
                $cache->put($counterKey, 0, $window);
                $cache->put($ipTrackingKey, [], $window);
            }

            $probingIps = (array) $cache->get($ipTrackingKey, []);
            if (!isset($probingIps[$event->ip])) {
                $probingIps[$event->ip] = time();
                $cache->put($ipTrackingKey, $probingIps, $window);
                $count = (int) $cache->increment($counterKey);
            } else {
                $count = (int) $cache->get($counterKey, 0);
            }
        };

        $store = method_exists($cache, 'getStore') ? $cache->getStore() : null;
        if ($store instanceof LockProvider) {
            $store->lock($this->getCacheKey('ds_lock:' . md5($target)), max(1, $window))->block(5, $update);
        } else {
            // Keep compatibility with legacy fake repositories without lock support.
            $update();
        }

        if ($count >= $threshold) {
            // Hash IPs to prevent information leakage about attacking infrastructure
            $hashedIps = array_map(
                static fn(string $ip): string => hash('sha256', $ip),
                array_keys($probingIps)
            );

            $fingerprint = hash('sha256', sprintf('distributed_spray:%s', $target));

            return new SecurityThreat(
                severity: $severity,
                threatType: 'distributed_spray',
                fingerprint: $fingerprint,
                metadata: [
                    'target_hash' => hash('sha256', $target),
                    'distinct_ips_count' => $count,
                    'sample_ips_hashed' => array_slice($hashedIps, 0, 10),
                    'threshold' => $threshold,
                    'window_seconds' => $window,
                    'last_ip' => $event->ip,
                ],
                ruleIdentifier: $this->identifier()
            );
        }

        return null;
    }
}
