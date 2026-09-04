<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Rules;

use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\DTO\SecurityThreat;

/**
 * Detects distributed spray attacks where multiple distinct IPs probe the same account identifier.
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
        $cacheKey = $this->getCacheKey(md5($target));

        $cache = $this->getCache();
        $now = time();

        /** @var array<string, int> $probingIps */
        $probingIps = (array) $cache->get($cacheKey, []);
        $probingIps = array_filter(
            $probingIps,
            static fn (int $ts): bool => ($now - $ts) <= $window
        );

        $probingIps[$event->ip] = $now;

        $cache->put($cacheKey, $probingIps, $window);

        if (count($probingIps) >= $threshold) {
            $fingerprint = hash('sha256', sprintf('distributed_spray:%s', $target));

            return new SecurityThreat(
                severity: $severity,
                threatType: 'distributed_spray',
                fingerprint: $fingerprint,
                metadata: [
                    'identifier' => $target,
                    'distinct_ips_count' => count($probingIps),
                    'sample_ips' => array_slice(array_keys($probingIps), 0, 10),
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
