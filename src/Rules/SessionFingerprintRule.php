<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Rules;

use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\DTO\SecurityThreat;

/**
 * Detects session hijacking and cookie theft from infected client devices.
 * Identifies when a valid session token is abruptly replayed from a disparate
 * network subnet or contradictory client environment.
 */
class SessionFingerprintRule extends AbstractDetectionRule
{
    public function identifier(): string
    {
        return 'session_fingerprint';
    }

    public function name(): string
    {
        return 'Session Fingerprint & Hijack Detector';
    }

    public function evaluate(SecurityEvent $event): ?SecurityThreat
    {
        if (! $this->isEnabled()) {
            return null;
        }

        $sessionId = $event->metadata['session_id'] ?? null;
        if (! is_string($sessionId) || $sessionId === '') {
            return null;
        }

        $cache = $this->getCache();
        $sessionHash = hash('sha256', $sessionId);
        $fingerprintKey = $this->getCacheKey("session:{$sessionHash}");

        $currentSubnet = $this->extractSubnet($event->ip);
        $currentUaHash = hash('sha256', $event->userAgent ?: 'empty');

        $stored = $cache->get($fingerprintKey);

        if (! is_array($stored)) {
            // First time seeing this session: establish baseline
            $ttl = (int) $this->getConfig('session_ttl', 7200); // 2 hours default
            $cache->put($fingerprintKey, [
                'subnet' => $currentSubnet,
                'ua_hash' => $currentUaHash,
                'initial_ip' => $event->ip,
                'user_agent' => $event->userAgent,
                'created_at' => time(),
            ], $ttl);

            return null;
        }

        $mismatches = [];

        // Check if User-Agent changed mid-session
        if ($stored['ua_hash'] !== $currentUaHash) {
            $mismatches[] = 'user_agent_drift';
        }

        // Check if IP subnet drifted beyond tolerance
        if ($currentSubnet !== 'unknown' && $stored['subnet'] !== $currentSubnet) {
            $mismatches[] = 'network_subnet_drift';
        }

        if (! empty($mismatches)) {
            $severity = count($mismatches) > 1 ? 'critical' : (string) $this->getConfig('severity', 'high');
            $fingerprint = hash('sha256', sprintf('session_hijack:%s:%s', $sessionHash, implode('+', $mismatches)));

            $metadata = [
                'session_hash' => $sessionHash,
                'identifier_hash' => hash('sha256', $event->identifier),
                'current_ip' => $event->ip,
                'initial_ip' => $stored['initial_ip'] ?? null,
                'current_ua_hash' => hash('sha256', $event->userAgent ?: 'empty'),
                'initial_ua_hash' => hash('sha256', $stored['user_agent'] ?? ''),
                'mismatches' => $mismatches,
                'reasons' => 'Session cookie was presented with contradictory network subnet or client signature',
            ];

            // Fire official event for application-level action (e.g. revoke tokens, force re-auth)
            event(new \Mixudev\SecurityDefense\Events\SecuritySessionCompromised(
                userId: (string) $event->identifier,
                ip: $event->ip,
                reason: implode(', ', $mismatches),
                context: $metadata
            ));

            return new SecurityThreat(
                severity: $severity,
                threatType: 'session_hijack_suspected',
                fingerprint: $fingerprint,
                metadata: $metadata,
                ruleIdentifier: $this->identifier()
            );
        }

        return null;
    }

    /**
     * Extract /24 IPv4 subnet or /48 IPv6 subnet to tolerate ISP DHCP changes.
     */
    protected function extractSubnet(string $ip): string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $parts = explode('.', $ip);

            return count($parts) === 4 ? sprintf('%s.%s.%s.0/24', $parts[0], $parts[1], $parts[2]) : 'unknown';
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $parts = explode(':', $ip);

            return count($parts) >= 3 ? sprintf('%s:%s:%s::/48', $parts[0], $parts[1], $parts[2]) : 'unknown';
        }

        return 'unknown';
    }
}
