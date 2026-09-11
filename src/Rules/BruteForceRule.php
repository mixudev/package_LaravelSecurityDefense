<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Rules;

use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\DTO\SecurityThreat;
/**
 * Detects brute force attempts targeting a single account identifier.
 * Atomic counter eliminates race condition on parallel requests.
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

        $cache = $this->getCache();
        $counterKey = $this->getCacheKey(md5($target) . ':count');
        $windowKey = $this->getCacheKey(md5($target) . ':window');

        // Atomic seed: first request sets TTL; subsequent requests increment atomically.
        // add() instead of has()+put() so concurrent requests cannot zero-out an
        // already-incremented counter window.
        $cache->add($counterKey, 0, $window);
        $cache->add($windowKey, true, $window);
        $count = (int) $cache->increment($counterKey);

        if ($count >= $threshold) {
            $fingerprint = hash('sha256', sprintf('brute_force:%s', strtolower($target)));

            return new SecurityThreat(
                severity: $severity,
                threatType: 'brute_force',
                fingerprint: $fingerprint,
                metadata: [
                    'target_hash' => hash('sha256', $target),
                    'identifier_hash' => hash('sha256', $event->identifier),
                    'ip' => $event->ip,
                    'attempt_count' => $count,
                    'threshold' => $threshold,
                    'window_seconds' => $window,
                    'event_type' => $event->eventType,
                    'user_agent_hash' => hash('sha256', $event->userAgent ?: 'empty'),
                ],
                ruleIdentifier: $this->identifier()
            );
        }

        return null;
    }
}
