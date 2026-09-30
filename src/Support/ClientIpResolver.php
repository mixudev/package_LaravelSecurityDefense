<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Support;

use Illuminate\Http\Request;

/**
 * Resolves the authentic client address for security decisions.
 *
 * A forwarded header (X-Forwarded-For and friends) is attacker-controlled
 * unless the direct TCP peer is an explicitly configured reverse proxy.
 * When the peer is untrusted, the socket address wins and every forwarded
 * header is ignored.
 *
 * Single source of truth: EnsureLocalAccess and the dashboard authorization
 * gate must agree on the address, otherwise a request accepted by one is
 * rejected (or worse, accepted) by the other.
 */
final class ClientIpResolver
{
    /**
     * @param array<int, string> $trustedProxies
     */
    public static function resolve(Request $request, array $trustedProxies): string
    {
        $peer = (string) ($request->server->get('REMOTE_ADDR') ?? '');

        if ($peer !== '' && ! in_array($peer, $trustedProxies, true)) {
            return $peer;
        }

        return (string) $request->ip();
    }
}
