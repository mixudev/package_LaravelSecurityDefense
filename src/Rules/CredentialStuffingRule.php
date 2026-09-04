<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Rules;

use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\DTO\SecurityThreat;

/**
 * Detects credential stuffing attempts where a single IP probes multiple distinct account identifiers.
 */
class CredentialStuffingRule extends AbstractDetectionRule
{
    public function identifier(): string
    {
        return 'credential_stuffing';
    }

    public function name(): string
    {
        return 'Credential Stuffing Detector';
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

        $threshold = (int) $this->getConfig('threshold', 8);
        $window = (int) $this->getConfig('window', 120);
        $severity = (string) $this->getConfig('severity', 'critical');

        $ip = $event->ip;
        $cacheKey = $this->getCacheKey(md5($ip));

        $cache = $this->getCache();
        $now = time();

        /** @var array<string, int> $targetedAccounts */
        $targetedAccounts = (array) $cache->get($cacheKey, []);
        $targetedAccounts = array_filter(
            $targetedAccounts,
            static fn (int $ts): bool => ($now - $ts) <= $window
        );

        $targetedAccounts[strtolower($event->identifier)] = $now;

        $cache->put($cacheKey, $targetedAccounts, $window);

        if (count($targetedAccounts) >= $threshold) {
            $fingerprint = hash('sha256', sprintf('credential_stuffing:%s', $ip));

            return new SecurityThreat(
                severity: $severity,
                threatType: 'credential_stuffing',
                fingerprint: $fingerprint,
                metadata: [
                    'ip' => $ip,
                    'distinct_identifiers_count' => count($targetedAccounts),
                    'sample_identifiers' => array_slice(array_keys($targetedAccounts), 0, 10),
                    'threshold' => $threshold,
                    'window_seconds' => $window,
                    'user_agent' => $event->userAgent,
                ],
                ruleIdentifier: $this->identifier()
            );
        }

        return null;
    }
}
