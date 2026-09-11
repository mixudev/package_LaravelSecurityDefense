<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Rules;

use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\DTO\SecurityThreat;
/**
 * Detects reconnaissance probing for sensitive files/directories (e.g. .env, .git, wp-login, phpinfo).
 * Atomic counter eliminates race condition on parallel requests.
 */
class PathReconnaissanceRule extends AbstractDetectionRule
{
    public function identifier(): string
    {
        return 'path_reconnaissance';
    }

    public function name(): string
    {
        return 'Path Reconnaissance & Vulnerability Scanner Detector';
    }

    /**
     * Patterns of sensitive paths scanned by reconnaissance tools.
     *
     * @var array<string>
     */
    protected array $sensitivePatterns = [
        '/\.env($|\.)/i',
        '/\.git(\/|$)/i',
        '/\.aws\//i',
        '/(wp-admin|wp-login\.php|xmlrpc\.php)/i',
        '/(phpinfo(\.php)?|info\.php)/i',
        '/(actuator|console|server-status)/i',
        '/(storage\/logs|\.log$)/i',
        '/(\.bak|\.old|\.sql|\.tar\.gz|\.zip)$/i',
        '/(config\.json|\.dockerenv|docker-compose\.yml)/i',
    ];

    public function evaluate(SecurityEvent $event): ?SecurityThreat
    {
        if (!$this->isEnabled()) {
            return null;
        }

        $path = (string) ($event->metadata['path'] ?? '');
        if ($path === '') {
            return null;
        }

        if (!$this->isSensitivePath($path)) {
            return null;
        }

        $threshold = (int) $this->getConfig('threshold', 3);
        $window = (int) $this->getConfig('window', 120);
        $severity = (string) $this->getConfig('severity', 'high');

        $ip = $event->ip;

        $cache = $this->getCache();
        $counterKey = $this->getCacheKey('probes_count:' . md5($ip));
        $windowKey = $this->getCacheKey('probes_window:' . md5($ip));

        // Atomic seed: add() cannot zero-out an incremented counter under concurrency.
        $cache->add($counterKey, 0, $window);
        $cache->add($windowKey, true, $window);
        $count = (int) $cache->increment($counterKey);

        if ($count >= $threshold) {
            $fingerprint = hash('sha256', sprintf('path_reconnaissance:%s', $ip));

            return new SecurityThreat(
                severity: $severity,
                threatType: 'path_reconnaissance',
                fingerprint: $fingerprint,
                metadata: [
                    'ip' => $ip,
                    'probe_count' => $count,
                    'threshold' => $threshold,
                    'window_seconds' => $window,
                    'last_probed_path' => $path,
                    'user_agent' => $event->userAgent,
                ],
                ruleIdentifier: $this->identifier()
            );
        }

        return null;
    }

    /**
     * Check whether a given path matches sensitive reconnaissance patterns.
     */
    public function isSensitivePath(string $path): bool
    {
        $normalized = '/' . ltrim($path, '/');

        foreach ($this->sensitivePatterns as $pattern) {
            if (preg_match($pattern, $normalized)) {
                return true;
            }
        }

        return false;
    }
}
