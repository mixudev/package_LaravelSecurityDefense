<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Rules;

use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\DTO\SecurityThreat;

/**
 * Detects contradictory HTTP client headers (e.g. tools mimicking browser User-Agents
 * but lacking fundamental browser headers like Accept-Language or Sec-Fetch-*).
 */
class HttpHeaderConsistencyRule extends AbstractDetectionRule
{
    public function identifier(): string
    {
        return 'header_consistency';
    }

    public function name(): string
    {
        return 'HTTP Header Consistency & Bot Detector';
    }

    public function evaluate(SecurityEvent $event): ?SecurityThreat
    {
        if (! $this->isEnabled()) {
            return null;
        }

        $headers = $event->metadata['headers'] ?? [];
        if (! is_array($headers) || empty($headers)) {
            return null;
        }

        // Normalize header keys to lowercase
        $normalizedHeaders = [];
        foreach ($headers as $k => $v) {
            $normalizedHeaders[strtolower((string) $k)] = is_array($v) ? implode(',', $v) : (string) $v;
        }

        $ua = strtolower($event->userAgent ?: ($normalizedHeaders['user-agent'] ?? ''));
        if ($ua === '') {
            return null;
        }

        $anomalies = [];

        // Condition 1: Modern Browser User-Agent (Chrome/Edge/Firefox/Safari) but missing Accept-Language
        $isBrowserUa = str_contains($ua, 'mozilla') || str_contains($ua, 'chrome') || str_contains($ua, 'safari');
        if ($isBrowserUa) {
            if (! isset($normalizedHeaders['accept-language'])) {
                $anomalies[] = 'browser_ua_without_accept_language';
            }

            // Modern Chromium browsers always send Sec-Fetch-Mode or Sec-CH-UA on navigation/XHR
            if (str_contains($ua, 'chrome') && ! str_contains($ua, 'mobile')) {
                $hasSecFetch = isset($normalizedHeaders['sec-fetch-mode']) || isset($normalizedHeaders['sec-ch-ua']);
                if (! $hasSecFetch) {
                    $anomalies[] = 'chromium_ua_missing_sec_fetch_headers';
                }
            }
        }

        // Condition 2: Firefox claiming Chrome client hints
        if (str_contains($ua, 'firefox') && isset($normalizedHeaders['sec-ch-ua'])) {
            $anomalies[] = 'firefox_with_chromium_client_hints';
        }

        if (! empty($anomalies)) {
            $severity = (string) $this->getConfig('severity', 'medium');
            $fingerprint = hash('sha256', sprintf('header_inconsistency:%s:%s', $event->ip, implode('+', $anomalies)));

            return new SecurityThreat(
                severity: $severity,
                threatType: 'header_inconsistency_bot',
                fingerprint: $fingerprint,
                metadata: [
                    'ip' => $event->ip,
                    'user_agent' => $event->userAgent,
                    'anomalies' => $anomalies,
                    'reasons' => 'HTTP headers contradict claimed User-Agent (scripted client impersonating browser)',
                ],
                ruleIdentifier: $this->identifier()
            );
        }

        return null;
    }
}
