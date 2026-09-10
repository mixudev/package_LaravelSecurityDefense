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

        // Set nonce before rendering so dashboard views can attach it to scripts.
        if (! $request->attributes->has('csp_nonce')) {
            $request->attributes->set('csp_nonce', base64_encode(random_bytes(16)));
        }
        $nonce = (string) $request->attributes->get('csp_nonce');

        /** @var Response $response */
        $response = $next($request);

        // Apply CSP Header if response is HTML
        $contentType = (string) $response->headers->get('Content-Type', '');
        if ($contentType === '' || str_contains($contentType, 'text/html')) {
            $policy = config('security-defense.csp_armor.policy');

            if (! $policy) {
                // Default zero-compromise production CSP policy
                $policy = "default-src 'self'; script-src 'self' 'nonce-{$nonce}' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' https: data:; object-src 'none'; base-uri 'self'; frame-ancestors 'self';";
            } else {
                $policy = str_replace('{nonce}', $nonce, $policy);
            }

            $headerName = config('security-defense.csp_armor.report_only', false)
                ? 'Content-Security-Policy-Report-Only'
                : 'Content-Security-Policy';

            if (! $response->headers->has($headerName)) {
                $response->headers->set($headerName, $policy);
            }
        }

        return $response;
    }
}
