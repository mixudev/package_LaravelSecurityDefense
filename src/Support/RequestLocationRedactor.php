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

        $path = $request->path();

        // Unresolved routes (404 before the router finishes, or global
        // middleware that runs pre-routing) still carry the opaque prefix in
        // $request->path(), so mask long hex-like segments unconditionally.
        $masked = preg_replace(
            '~(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{32,160})(?![A-Za-z0-9_-])~',
            '[redacted]',
            $path
        );

        return substr(is_string($masked) ? $masked : $path, 0, 500);
    }

    public static function url(Request $request): string
    {
        $routeName = $request->route()?->getName();
        if (is_string($routeName) && str_starts_with($routeName, 'security-defense.')) {
            return '[dashboard-route:' . $routeName . ']';
        }

        // Never trust request Host or forwarded headers in persisted telemetry.
        // They are attacker-controlled unless host app explicitly configures app.url.
        $configured = parse_url((string) config('app.url', ''), PHP_URL_SCHEME)
            && parse_url((string) config('app.url', ''), PHP_URL_HOST)
            ? rtrim((string) config('app.url'), '/')
            : '';
        $location = ($configured !== '' ? $configured : '[untrusted-host]')
            . '/' . ltrim($request->path(), '/');

        // Never retain query strings: signed URLs, reset tokens, credentials.
        return substr($location, 0, 1000);
    }
}
