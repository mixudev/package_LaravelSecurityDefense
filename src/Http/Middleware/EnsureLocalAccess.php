<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\RateLimiter;
use Mixudev\SecurityDefense\Services\DashboardAccessPolicy;
use Symfony\Component\HttpFoundation\Response;

/**
 * Middleware ensuring the Security Defense dashboard is accessible strictly in local environments.
 * Prevents unintentional production exposure of security alerts and SIEM telemetry.
 */
class EnsureLocalAccess
{
    /**
     * Handle an incoming request.
     *
     * @param Request $request
     * @param Closure(Request): (Response) $next
     * @return Response
     */
    public function handle(Request $request, Closure $next): Response
    {
        // 1. Check if dashboard is enabled globally
        if (!(bool) config('security-defense.dashboard.enabled', true)) {
            abort(404);
        }

        $clientIp = (string) $request->ip();
        $localOnly = (bool) config('security-defense.dashboard.local_only', true);
        $allowedIps = array_values(array_filter((array) config('security-defense.dashboard.allowed_ips', ['127.0.0.1', '::1']), 'is_string'));

        $authorized = false;
        $denyReason = 'policy';

        if ($localOnly) {
            // Local mode is a strict loopback-only boundary. A host Gate must
            // NOT be able to elevate a remote/non-loopback request into the
            // local dashboard: local access always requires a local env AND a
            // loopback/configured-local client address.
            $isLocalEnv = app()->environment('local');
            $ipPolicy = new DashboardAccessPolicy($allowedIps, []);
            $authorized = $isLocalEnv && $ipPolicy->allows($clientIp);
            $denyReason = (!$isLocalEnv) ? 'environment' : 'ip';
        } else {
            // Public exposure is opt-in and fail-closed.
            $public = (array) config('security-defense.dashboard.public', []);
            if (!(bool) ($public['enabled'] ?? false)) {
                $denyReason = 'public-disabled';
            } elseif (!$this->networkAllows($clientIp, $public)) {
                $denyReason = 'ip';
            } elseif ((bool) ($public['require_authenticated_user'] ?? true) && $request->user() === null) {
                $denyReason = 'unauthenticated';
            } elseif (!$this->gateAllows($public, $request)) {
                $denyReason = 'gate';
            } elseif ($this->stepUpDenied($public, $request)) {
                $denyReason = 'step-up';
            } else {
                $authorized = true;
            }
        }

        if (!$authorized) {
            $isLoopback = in_array($clientIp, ['127.0.0.1', '::1', 'localhost'], true);
            $public = (array) config('security-defense.dashboard.public', []);

            // Throttle remote denials in BOTH modes (loopback stays unthrottled
            // for operator diagnostics). Prevents log-flood DoS + free probing
            // of the gate/dashboard in local mode and counter-splitting across
            // the two endpoints in public mode.
            if ((!$localOnly && $denyReason !== 'public-disabled') || !$isLoopback) {
                if ($this->isRateLimited($clientIp, $public)) {
                    $denyReason = 'rate-limited';
                }
            }

            $this->deny($request, $localOnly, $denyReason);
        }

        $response = $next($request);

        return $response
            ->header('Cache-Control', 'no-store, no-cache, must-revalidate, private')
            ->header('Pragma', 'no-cache')
            ->header('X-Content-Type-Options', 'nosniff')
            ->header('X-Frame-Options', 'DENY')
            ->header('Referrer-Policy', 'no-referrer');
    }

    private function networkAllows(string $clientIp, array $public): bool
    {
        $policy = new DashboardAccessPolicy(
            (array) ($public['allowed_ips'] ?? []),
            (array) ($public['allowed_cidrs'] ?? [])
        );

        return $policy->allows($clientIp);
    }

    private function gateAllows(array $public, Request $request): bool
    {
        $gateName = $public['authorization_gate'] ?? null;

        if (!is_string($gateName) || $gateName === '') {
            return false;
        }

        if (!Gate::has($gateName)) {
            return false;
        }

        return Gate::allows($gateName, [$request->user() ?? null, $request]);
    }

    private function stepUpDenied(array $public, Request $request): bool
    {
        if (!(bool) ($public['require_step_up'] ?? false)) {
            return false;
        }

        $gateName = $public['step_up_gate'] ?? null;

        if (!is_string($gateName) || $gateName === '') {
            return true; // fail closed when step-up required but no gate configured
        }

        if (!Gate::has($gateName)) {
            return true; // fail closed when gate missing
        }

        return !Gate::allows($gateName, [$request->user() ?? null, $request]);
    }

    /**
     * Rate limit public-mode denials aggressively so remote scanners get 429.
     */
    private function isRateLimited(string $clientIp, array $public): bool
    {
        $limit = (array) ($public['rate_limit'] ?? []);
        $maxAttempts = max(1, (int) ($limit['max_attempts'] ?? 10));
        $decaySeconds = max(1, (int) ($limit['decay_seconds'] ?? 60));

        $rateKey = 'security-defense:dashboard-access:' . hash('sha256', $clientIp);

        // Every public-mode denial attempt consumes a slot (atomic hit).
        RateLimiter::hit($rateKey, $decaySeconds);

        return RateLimiter::tooManyAttempts($rateKey, $maxAttempts);
    }

    private function safeLogPath(Request $request): string
    {
        $routeName = $request->route()?->getName();
        if (is_string($routeName) && str_starts_with($routeName, 'security-defense.')) {
            return '[dashboard-route:' . $routeName . ']';
        }

        $path = $request->path();

        return substr($path, 0, 200);
    }

    private function deny(Request $request, bool $localOnly, string $reason): void
    {
        Log::warning('Security Defense dashboard access denied.', [
            'reason' => $reason,
            'path' => $this->safeLogPath($request),
            'user_id' => $request->user()?->getAuthIdentifier(),
            'local_only' => $localOnly,
        ]);

        if ($reason === 'rate-limited') {
            abort(429, 'Too Many Requests.');
        }

        abort(403, 'Forbidden.');
    }
}
