<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
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

        // 2. Enforce strict local-only policy
        $localOnly = (bool) config('security-defense.dashboard.local_only', true);

        if ($localOnly) {
            $isLocalEnv = app()->environment('local');
            $allowedIps = (array) config('security-defense.dashboard.allowed_ips', ['127.0.0.1', '::1']);
            $clientIp = $request->ip();
            $isAllowedIp = in_array($clientIp, $allowedIps, true) || $clientIp === 'localhost';

            // Allow if local environment AND allowed local IP
            $isAuthorized = $isLocalEnv && $isAllowedIp;

            // Host application can optionally define a custom Gate
            if (Gate::has('viewSecurityDefenseDashboard')) {
                $isAuthorized = Gate::allows('viewSecurityDefenseDashboard');
            }

            if (!$isAuthorized) {
                abort(403, 'Forbidden: The Security Defense dashboard is restricted to local environment access.');
            }
        }

        return $next($request);
    }
}
