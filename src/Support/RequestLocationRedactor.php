<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Support;

use Illuminate\Http\Request;

/**
 * Redacts dashboard capability paths before request locations enter telemetry.
 */
final class RequestLocationRedactor
{
    public static function path(Request $request): string
    {
        $routeName = $request->route()?->getName();
        if (is_string($routeName) && str_starts_with($routeName, 'security-defense.')) {
            return '[dashboard-route:' . $routeName . ']';
        }

        return self::replaceToken(substr($request->path(), 0, 500));
    }

    public static function url(Request $request): string
    {
        $routeName = $request->route()?->getName();
        if (is_string($routeName) && str_starts_with($routeName, 'security-defense.')) {
            return '[dashboard-route:' . $routeName . ']';
        }

        // Never retain query strings in telemetry. They commonly carry signed
        // URLs, reset tokens, and provider credentials.
        return self::replaceToken(substr($request->getSchemeAndHttpHost() . '/' . ltrim($request->path(), '/'), 0, 1000));
    }

    private static function replaceToken(string $value): string
    {
        $token = OpaqueDashboardPathResolver::token();

        return is_string($token) && $token !== ''
            ? str_replace($token, '[REDACTED]', $value)
            : $value;
    }
}
