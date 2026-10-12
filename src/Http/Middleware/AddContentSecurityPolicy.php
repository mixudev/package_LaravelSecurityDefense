<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Content Security Policy Middleware
 *
 * Menambahkan header CSP yang membedakan environment:
 *   - local/testing  : Content-Security-Policy-Report-Only (tidak blokir, hanya laporan)
 *   - production     : Content-Security-Policy (enforcement penuh)
 *
 * Konfigurasi via config('security-defense.csp.*') atau .env:
 *   SECURITY_CSP_ENABLED=true
 *   SECURITY_CSP_REPORT_ONLY=false   (production: false, local: true otomatis)
 *   SECURITY_CSP_REPORT_URI=/security/csp-report
 */
class AddContentSecurityPolicy
{
    /**
     * Handle an incoming request.
     *
     * @param Closure(Request): Response $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        if (!(bool) config('security-defense.csp.enabled', true)) {
            return $response;
        }

        $policy = $this->buildPolicy();

        if (empty($policy)) {
            return $response;
        }

        // Gunakan Report-Only di local/testing ATAU jika dikonfigurasi eksplisit
        $isReportOnly = $this->isReportOnly();
        $headerName   = $isReportOnly
            ? 'Content-Security-Policy-Report-Only'
            : 'Content-Security-Policy';

        $response->headers->set($headerName, $policy);

        // Tambah header sekuriti standar lain (defense-in-depth)
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('X-Frame-Options', 'SAMEORIGIN');
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');

        return $response;
    }

    /**
     * Build CSP directive string dari config.
     */
    protected function buildPolicy(): string
    {
        $appUrl = rtrim((string) config('app.url', ''), '/');

        // Font & style sources
        $styleSrc    = "'self' https://fonts.bunny.net";
        $fontSrc     = "'self' https://fonts.bunny.net";
        $connectSrc  = "'self'";
        $imgSrc      = "'self' data:";
        $mediaSrc    = "'self'";
        $objectSrc   = "'none'";
        $frameSrc    = "'none'";
        $baseUri     = "'self'";
        $formAction  = "'self'";

        // Script: 'self' + Tailwind CDN (hanya jika enabled di config)
        $allowTailwindCdn = (bool) config('security-defense.csp.allow_tailwind_cdn', false);
        $scriptSrc = "'self'";
        if ($allowTailwindCdn) {
            $scriptSrc .= ' https://cdn.tailwindcss.com';
        }

        // Alpine.js CDN: hanya izinkan jika bukan Vite mode
        $allowAlpineCdn = (bool) config('security-defense.csp.allow_alpine_cdn', false);
        if ($allowAlpineCdn) {
            $scriptSrc .= ' https://cdn.jsdelivr.net';
        }

        // Nonce: jika host app ingin memakai nonce, set di config
        $nonce = (string) config('security-defense.csp.nonce', '');
        if ($nonce !== '') {
            $scriptSrc .= " 'nonce-{$nonce}'";
        }

        // unsafe-inline script: hanya boleh di local/testing (inline theme engine)
        $isLocal  = app()->environment(['local', 'testing']);
        $isReport = $this->isReportOnly();
        if ($isLocal || $isReport) {
            // Di local, izinkan unsafe-inline agar theme engine & inline script berjalan
            $scriptSrc .= " 'unsafe-inline'";
            $styleSrc  .= " 'unsafe-inline'";
        }

        // Report URI
        $reportUri = (string) config('security-defense.csp.report_uri', '');

        $directives = [
            "default-src 'self'",
            "script-src {$scriptSrc}",
            "style-src {$styleSrc}",
            "font-src {$fontSrc}",
            "img-src {$imgSrc}",
            "media-src {$mediaSrc}",
            "connect-src {$connectSrc}",
            "object-src {$objectSrc}",
            "frame-src {$frameSrc}",
            "base-uri {$baseUri}",
            "form-action {$formAction}",
            "upgrade-insecure-requests",
        ];

        // Hanya tambah upgrade-insecure-requests di production (local pakai HTTP)
        if ($isLocal) {
            // Hapus upgrade-insecure-requests di local agar tidak break HTTP dev server
            $directives = array_filter($directives, fn ($d) => $d !== 'upgrade-insecure-requests');
        }

        if ($reportUri !== '') {
            $directives[] = "report-uri {$reportUri}";
        }

        return implode('; ', $directives);
    }

    /**
     * Tentukan apakah harus memakai Report-Only mode.
     *
     * Logic:
     *   - local/testing → selalu Report-Only (tidak blokir developer)
     *   - config eksplisit override segalanya jika set
     */
    protected function isReportOnly(): bool
    {
        // Config eksplisit selalu menang
        if (config()->has('security-defense.csp.report_only')) {
            return (bool) config('security-defense.csp.report_only');
        }

        // Default: Report-Only di local/testing, Enforce di production
        return app()->environment(['local', 'testing']);
    }
}
