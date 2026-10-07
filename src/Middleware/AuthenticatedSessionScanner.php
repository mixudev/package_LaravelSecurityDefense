<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Mixudev\SecurityDefense\Services\SecurityDefenseManager;
use Mixudev\SecurityDefense\Support\RequestLocationRedactor;
use Throwable;

/**
 * Middleware monitoring post-authentication user session activity.
 * Tracks session hijacking, client header anomalies, and behavioral velocity.
 */
class AuthenticatedSessionScanner
{
    public function __construct(
        protected SecurityDefenseManager $defenseManager,
    ) {
    }

    /**
     * Keep only low-risk diagnostic headers. Never persist auth, cookie, proxy,
     * referer, or arbitrary host headers into session telemetry.
     *
     * @return array<string, string>
     */
    private function safeHeaders(Request $request): array
    {
        $allowed = ['accept', 'content-type', 'user-agent'];
        $result = [];

        foreach ($allowed as $header) {
            $value = $request->headers->get($header);
            if (is_string($value)) {
                $result[$header] = substr($value, 0, 256);
            }
        }

        return $result;
    }

    /**
     * Handle incoming authenticated request.
     *
     * @param Request $request
     * @param Closure(Request): mixed $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next): mixed
    {
        if (! config('security-defense.enabled', true) || ! config('security-defense.session_intelligence.enabled', true)) {
            return $next($request);
        }

        try {
            $user = $request->user() ?? (Auth::check() ? Auth::user() : null);
            if ($user !== null) {
                $sessionId = $request->hasSession() ? $request->session()->getId() : null;
                $identifier = (string) $user->getAuthIdentifier();

                $clientIp = \Mixudev\SecurityDefense\Support\ClientIpResolver::resolve(
                    $request,
                    (array) config('security-defense.dashboard.trusted_proxies', ['127.0.0.1', '::1'])
                );
                if ($clientIp === '') {
                    $clientIp = '127.0.0.1';
                }

                $threats = $this->defenseManager->record([
                    'ip' => $clientIp,
                    'identifier' => $identifier,
                    'eventType' => 'AuthenticatedSessionActivity',
                    'userAgent' => (string) ($request->userAgent() ?: ''),
                    'metadata' => [
                        // One-way fingerprint only: a raw session ID in
                        // telemetry (DB, alerts, queue, SIEM) is a replayable
                        // session credential if any sink leaks.
                        'session_hash' => is_string($sessionId) && $sessionId !== ''
                            ? hash('sha256', $sessionId)
                            : null,
                        'url' => RequestLocationRedactor::path($request),
                        'method' => $request->method(),
                        'headers' => $this->safeHeaders($request),
                    ],
                ]);

                // Check for immediate critical session hijacking
                if ((bool) config('security-defense.session_intelligence.block_on_hijack', false)) {
                    foreach ($threats as $threat) {
                        if ($threat->threatType === 'session_hijack_suspected' && $threat->severity === 'critical') {
                            abort(403, 'Session compromised or hijacked. Access denied.');
                        }
                    }
                }
            }
        } catch (\Symfony\Component\HttpKernel\Exception\HttpExceptionInterface $e) {
            throw $e;
        } catch (Throwable $e) {
            // Telemetry failures must not disrupt ordinary user flow.
            report($e);
        }

        return $next($request);
    }
}
