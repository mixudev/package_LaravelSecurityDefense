<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Transparent Content Security Policy (CSP) Response Armor.
 * Enforces nonce-based or strict CSP headers to neutralize XSS even if
 * malicious payloads are accidentally rendered unescaped by developers.
 */
class ContentSecurityPolicyArmor
{
    /**
     * Handle an incoming request.
     *
     * @param Request $request
     * @param Closure(Request): Response $next
     * @return Response
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (! config('security-defense.csp_armor.enabled', true)) {
            return $next($request);
        }

        // Always generate the nonce here. Never trust a pre-seeded request
        // attribute: another middleware may have copied attacker-controlled input.
        $nonce = base64_encode(random_bytes(16));
        $request->attributes->set('csp_nonce', $nonce);

        /** @var Response $response */
        $response = $next($request);

        // Apply CSP only to non-empty HTML responses. An absent content type is
        // not proof of HTML and must not cause nonce-bearing headers on 204/304.
        $contentType = (string) $response->headers->get('Content-Type', '');
        if (! $response->isEmpty() && str_contains($contentType, 'text/html')) {
            $policy = config('security-defense.csp_armor.policy');

            if (! $policy) {
                // Default zero-compromise production CSP policy
                $policy = "default-src 'self'; script-src 'self' 'nonce-{$nonce}' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' https: data:; object-src 'none'; base-uri 'self'; frame-ancestors 'self';";
            } else {
                $policy = str_replace('{nonce}', $nonce, $policy);
            }

            $reportOnly = (bool) config('security-defense.csp_armor.report_only', false);
            $headerName = $reportOnly
                ? 'Content-Security-Policy-Report-Only'
                : 'Content-Security-Policy';
            $oppositeHeaderName = $reportOnly
                ? 'Content-Security-Policy'
                : 'Content-Security-Policy-Report-Only';

            // One mode must be authoritative. Leaving a downstream opposite
            // header in place makes the effective policy depend on middleware
            // order and can silently disable enforcement in report-only mode.
            $response->headers->remove($oppositeHeaderName);
            $response->headers->set($headerName, $policy);
        }

        return $response;
    }
}
