<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Http\Controllers;

use Illuminate\Http\Response;
use Illuminate\Routing\Controller;
use Mixudev\SecurityDefense\Support\OpaqueDashboardPathResolver;

/**
 * Verification gate shown at the predictable dashboard entry point
 * when opaque-path mode is active. The opaque URL (token-bearing)
 * is generated server-side only — never emitted in HTML or logs.
 */
class PortalController extends Controller
{
    /**
     * Render the secure-entry verification gate.
     */
    public function index()
    {
        return view('security-defense::portal');
    }

    /**
     * Gate action — passes through EnsureLocalAccess, then redirects
     * to the opaque dashboard URL. Token stays in Location header only.
     */
    public function enter(): Response
    {
        $token = OpaqueDashboardPathResolver::token();
        if ($token === null) {
            abort(404);
        }

        // Relative Location — never absolutize via request Host (Host header
        // poisoning would turn this into an open redirect shipping the token
        // to an attacker-controlled origin).
        return new Response('', 302, ['Location' => '/' . $token]);
    }
}
