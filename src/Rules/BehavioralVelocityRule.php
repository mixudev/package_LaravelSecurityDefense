<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Rules;

use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\DTO\SecurityThreat;

/**
 * Detects abnormal request velocity and scraping behavior by authenticated accounts.
 * Prevents compromised accounts or bots from performing bulk exfiltration unnoticed.
 */
class BehavioralVelocityRule extends AbstractDetectionRule
{
    public function identifier(): string
    {
        return 'behavioral_velocity';
    }

    public function name(): string
    {
        return 'Post-Authentication Velocity & Scraper Detector';
    }

    public function evaluate(SecurityEvent $event): ?SecurityThreat
    {
        if (! $this->isEnabled()) {
            return null;
        }

        // Only evaluate authenticated user sessions or explicit identifiers
        if ($event->identifier === '' || $event->identifier === 'anonymous') {
            return null;
        }

        $threshold = (int) $this->getConfig('threshold', 120); // Requests per minute
        $window = (int) $this->getConfig('window', 60);         // 60 seconds
        $severity = (string) $this->getConfig('severity', 'high');

        $cache = $this->getCache();
        $target = $event->identifier;
        $counterKey = $this->getCacheKey(md5($target) . ':velocity:count');
        $windowKey = $this->getCacheKey(md5($target) . ':velocity:window');

        // Atomic seed: add() cannot zero-out an incremented counter under concurrency.
        $cache->add($counterKey, 0, $window);
        $cache->add($windowKey, true, $window);

        $count = (int) $cache->increment($counterKey);

        if ($count >= $threshold) {
            $fingerprint = hash('sha256', sprintf('behavioral_velocity:%s', $target));

            return new SecurityThreat(
                severity: $count >= ($threshold * 2) ? 'critical' : $severity,
                threatType: 'suspicious_velocity_scraping',
                fingerprint: $fingerprint,
                metadata: [
                    'identifier' => $target,
                    'ip' => $event->ip,
                    'requests_in_window' => $count,
                    'threshold_rpm' => $threshold,
                    'window_seconds' => $window,
                    'user_agent' => $event->userAgent,
                    'reason' => 'Authenticated account exceeded human interaction speed threshold',
                ],
                ruleIdentifier: $this->identifier()
            );
        }

        return null;
    }
}
