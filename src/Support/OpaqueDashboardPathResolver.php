<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Support;

/**
 * Resolves the opaque dashboard path secret from the host environment.
 *
 * Security contract:
 * - The value is read from env at request time, NEVER from the published
 *   config cache (config:cache would freeze a secret into a world-readable
 *   file) and NEVER from ConfigWriterService overrides.
 * - When opaque path is enabled and no valid token is present, the dashboard
 *   must fail closed (route prefix falls back to a 404-only path).
 */
final class OpaqueDashboardPathResolver
{
    private const SEGMENT_PATTERN = '/^[A-Za-z0-9_-]{43,88}$/';

    public static function token(): ?string
    {
        $value = getenv('SECURITY_DEFENSE_DASHBOARD_PATH');
        if ($value === false) {
            $value = env('SECURITY_DEFENSE_DASHBOARD_PATH');
        }

        if (! is_string($value) || trim($value) === '') {
            return null;
        }

        $value = trim($value);

        // RFC-ish base64url segment. Reject anything that could be an encoded
        // separator, control char, or padding so no token ever double-acts as
        // a path traversal or subroute separator.
        if (preg_match(self::SEGMENT_PATTERN, $value) !== 1) {
            return null;
        }

        return $value;
    }

    /**
     * Effective dashboard path prefix.
     *
     * @return string A valid URL segment, or a 404-only path when opaque mode
     *                is enabled but the token is missing/malformed (fail closed).
     */
    public static function resolvePath(bool $opaqueEnabled, ?string $configuredPath = null): string
    {
        if (! $opaqueEnabled) {
            $configured = $configuredPath ?? 'security-defense';

            return $configured !== '' ? $configured : 'security-defense';
        }

        $token = self::token();

        return $token ?? '__opaque_dashboard_unreachable__';
    }
}