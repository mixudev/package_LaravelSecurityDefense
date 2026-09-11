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

        return substr($request->path(), 0, 500);
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
