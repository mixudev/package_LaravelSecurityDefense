<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Log;
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

        $isAuthorized = false;
        if ($localOnly) {
            $isLocalEnv = app()->environment('local');
            $allowedIps = (array) config('security-defense.dashboard.allowed_ips', ['127.0.0.1', '::1']);
            $clientIp = $request->ip();
            $isAllowedIp = in_array($clientIp, $allowedIps, true) || $clientIp === 'localhost';

            // Preserve local dashboard behavior; host Gate can override it.
            $isAuthorized = $isLocalEnv && $isAllowedIp;
        }

        // Non-local exposure is never public. Host application must provide an
        // authenticated/authorized Gate before sensitive dashboard routes open.
        if (Gate::has('viewSecurityDefenseDashboard')) {
            $isAuthorized = Gate::allows('viewSecurityDefenseDashboard');
        }

        if (! $isAuthorized) {
            Log::warning('Security Defense dashboard access denied.', [
                'ip' => $request->ip(),
                'path' => $request->path(),
                'user_id' => $request->user()?->getAuthIdentifier(),
                'local_only' => $localOnly,
            ]);
            abort(403, 'Forbidden.');
        }

        return $next($request);
    }
}
