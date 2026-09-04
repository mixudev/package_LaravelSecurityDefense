<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Rules;

use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\DTO\SecurityThreat;

/**
 * Detects brute force attempts targeting a single account identifier.
 */
class BruteForceRule extends AbstractDetectionRule
{
    public function identifier(): string
    {
        return 'brute_force';
    }

    public function name(): string
    {
        return 'Brute Force Attack Detector';
    }

    public function evaluate(SecurityEvent $event): ?SecurityThreat
    {
        if (!$this->isEnabled()) {
            return null;
        }

        $monitoredEvents = (array) $this->getConfig('events', ['LoginFailed', 'OTP_FAILED']);
        if (!in_array($event->eventType, $monitoredEvents, true)) {
            return null;
        }

        $threshold = (int) $this->getConfig('threshold', 10);
        $window = (int) $this->getConfig('window', 60);
        $severity = (string) $this->getConfig('severity', 'high');

        $target = $event->identifier !== 'anonymous' ? $event->identifier : $event->ip;
        $cacheKey = $this->getCacheKey(md5($target));

        $cache = $this->getCache();
        $now = time();

        /** @var array<int> $attempts */
        $attempts = (array) $cache->get($cacheKey, []);
        $attempts = array_filter($attempts, static fn (int $ts): bool => ($now - $ts) <= $window);
        $attempts[] = $now;

        $cache->put($cacheKey, array_values($attempts), $window);

        if (count($attempts) >= $threshold) {
            $fingerprint = hash('sha256', sprintf('brute_force:%s', strtolower($target)));

            return new SecurityThreat(
                severity: $severity,
                threatType: 'brute_force',
                fingerprint: $fingerprint,
                metadata: [
                    'target' => $target,
                    'identifier' => $event->identifier,
                    'ip' => $event->ip,
                    'attempt_count' => count($attempts),
                    'threshold' => $threshold,
                    'window_seconds' => $window,
                    'event_type' => $event->eventType,
                    'user_agent' => $event->userAgent,
                ],
                ruleIdentifier: $this->identifier()
            );
        }

        return null;
    }
}
