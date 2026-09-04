<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Rules;

use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\DTO\SecurityThreat;

/**
 * Detects attempts to bypass rate limiters via header spoofing or rapid identity cycling.
 */
class RateLimitBypassRule extends AbstractDetectionRule
{
    public function identifier(): string
    {
        return 'rate_limit_bypass';
    }

    public function name(): string
    {
        return 'Rate Limit Bypass Detector';
    }

    public function evaluate(SecurityEvent $event): ?SecurityThreat
    {
        if (!$this->isEnabled()) {
            return null;
        }

        $threshold = (int) $this->getConfig('threshold', 15);
        $window = (int) $this->getConfig('window', 60);
        $severity = (string) $this->getConfig('severity', 'medium');

        // Check for direct header manipulation indicators in metadata
        $headers = (array) ($event->metadata['headers'] ?? []);
        $forwardedFor = (string) ($headers['x-forwarded-for'] ?? '');

        $hasHeaderSpoof = false;
        $spoofReason = '';

        if ($forwardedFor !== '') {
            $ips = array_map('trim', explode(',', $forwardedFor));
            // Check for duplicate or bogus internal headers from WAN or abnormally long proxy chains
            if (count($ips) > 5) {
                $hasHeaderSpoof = true;
                $spoofReason = 'Abnormally long proxy chain detected in X-Forwarded-For header.';
            }
        }

        // Track rapid client-IP rotation per User-Agent/Subnet
        $uaKey = md5(sprintf('%s:%s', $event->userAgent, substr($event->ip, 0, 7)));
        $cacheKey = $this->getCacheKey('cycling:' . $uaKey);

        $cache = $this->getCache();
        $now = time();

        /** @var array<string, int> $cycledIps */
        $cycledIps = (array) $cache->get($cacheKey, []);
        $cycledIps = array_filter(
            $cycledIps,
            static fn (int $ts): bool => ($now - $ts) <= $window
        );

        $cycledIps[$event->ip] = $now;
        $cache->put($cacheKey, $cycledIps, $window);

        if ($hasHeaderSpoof || count($cycledIps) >= $threshold) {
            $fingerprint = hash('sha256', sprintf('rate_limit_bypass:%s:%s', $event->ip, $uaKey));

            return new SecurityThreat(
                severity: $hasHeaderSpoof ? 'high' : $severity,
                threatType: 'rate_limit_bypass',
                fingerprint: $fingerprint,
                metadata: [
                    'ip' => $event->ip,
                    'user_agent' => $event->userAgent,
                    'distinct_cycled_ips' => count($cycledIps),
                    'spoof_detected' => $hasHeaderSpoof,
                    'spoof_reason' => $spoofReason,
                    'threshold' => $threshold,
                    'window_seconds' => $window,
                ],
                ruleIdentifier: $this->identifier()
            );
        }

        return null;
    }
}
