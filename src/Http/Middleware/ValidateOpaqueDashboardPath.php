<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\URL;
use Mixudev\SecurityDefense\Support\DashboardCapability;

/** Consume one-time entry capability, then accept session-bound dashboard path. */
final class ValidateOpaqueDashboardPath
{
    public function __construct(private readonly DashboardCapability $capability)
    {
    }

    public function handle(Request $request, Closure $next): mixed
    {
        $candidate = (string) $request->route('opaque');
        $sessionId = (string) $request->session()->getId();
        if ($candidate === '' || $sessionId === '') {
            abort(404);
        }

        if (strlen($candidate) > 64) {
            $sessionPath = $this->capability->consume($candidate, $sessionId);
            if ($sessionPath === null) {
                abort(404);
            }

            $request->session()->put('security-defense.dashboard-authorized', true);
            $request->session()->put('security-defense.dashboard-session-path', $sessionPath);

            return redirect('/' . $sessionPath);
        }

        $sessionPath = (string) $request->session()->get('security-defense.dashboard-session-path');
        if (!$request->session()->get('security-defense.dashboard-authorized', false)
            || $sessionPath === ''
            || $sessionPath !== $candidate) {
            abort(404);
        }

        $request->attributes->set('security-defense.opaque-token', $candidate);
        URL::defaults(['opaque' => $candidate]);

        return $next($request);
    }
}
