<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Rules;

use Illuminate\Contracts\Cache\LockProvider;
use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\DTO\SecurityThreat;
/**
 * Detects credential stuffing attempts where a single IP probes multiple distinct account identifiers.
 * Atomic counter eliminates race condition on parallel requests.
 * Identifiers are hashed in metadata to prevent information leakage.
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
        $identifierKey = md5(strtolower($event->identifier));

        $cache = $this->getCache();
        $counterKey = $this->getCacheKey('cs_count:' . md5($ip));
        $windowKey = $this->getCacheKey('cs_window:' . md5($ip));
        $idTrackingKey = $this->getCacheKey('cs_ids:' . md5($ip));

        /** @var array<string, int> $targetedAccounts */
        $targetedAccounts = [];
        $count = 0;
        $update = function () use ($cache, $windowKey, $counterKey, $idTrackingKey, $window, $identifierKey, &$targetedAccounts, &$count): void {
            if (!$cache->has($windowKey)) {
                $cache->put($windowKey, true, $window);
                $cache->put($counterKey, 0, $window);
                $cache->put($idTrackingKey, [], $window);
            }

            $targetedAccounts = (array) $cache->get($idTrackingKey, []);
            if (!isset($targetedAccounts[$identifierKey])) {
                $targetedAccounts[$identifierKey] = time();
                $cache->put($idTrackingKey, $targetedAccounts, $window);
                $count = (int) $cache->increment($counterKey);
            } else {
                $count = (int) $cache->get($counterKey, 0);
            }
        };

        $store = method_exists($cache, 'getStore') ? $cache->getStore() : null;
        if ($store instanceof LockProvider) {
            $store->lock($this->getCacheKey('cs_lock:' . md5($ip)), max(1, $window))->block(5, $update);
        } else {
            // Keep compatibility with legacy fake repositories without lock support.
            $update();
        }

        if ($count >= $threshold) {
            // Hash identifiers to prevent information leakage
            $hashedList = array_map(
                static fn(string $id): string => hash('sha256', $id),
                array_keys($targetedAccounts)
            );

            $fingerprint = hash('sha256', sprintf('credential_stuffing:%s', $ip));

            return new SecurityThreat(
                severity: $severity,
                threatType: 'credential_stuffing',
                fingerprint: $fingerprint,
                metadata: [
                    'ip' => $ip,
                    'distinct_identifiers_count' => $count,
                    'sample_identifiers_hashed' => array_slice($hashedList, 0, 10),
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
