<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Http\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Routing\Controller;
use Illuminate\View\View;
use Mixudev\SecurityDefense\Services\DashboardOtpDispatcher;
use Mixudev\SecurityDefense\Services\DashboardOtpService;
use Mixudev\SecurityDefense\Support\ClientIpResolver;
use Mixudev\SecurityDefense\Support\DashboardCapability;

/**
 * Verification gate shown at the predictable dashboard entry point
 * when opaque-path mode is active. The opaque URL (token-bearing)
 * is generated server-side only — never emitted in HTML or logs.
 *
 * When dashboard.otp.enabled = true, the gateway becomes two-step:
 *
 *   1. POST /enter        - IP whitelist already enforced by EnsureLocalAccess;
 *                           issues a code and redirects to the code form.
 *   2. POST /verify-code  - validates the code, then redirects to the opaque path.
 *
 * When disabled (default), the original single-step flow is preserved.
 */
class PortalController extends Controller
{
    public function __construct(
        private readonly DashboardCapability $capability,
        private readonly DashboardOtpService $otpService,
        private readonly DashboardOtpDispatcher $otpDispatcher,
    ) {
    }

    /**
     * Render the secure-entry verification gate.
     */
    public function index(): View
    {
        return view('security-defense::portal');
    }

    /**
     * Gate action after IP whitelist passes.
     *
     * OTP disabled: issue capability and redirect to opaque path (v1 flow).
     * OTP enabled : issue & deliver a code, mark session pending, redirect to form.
     */
    public function enter(Request $request): Response|RedirectResponse
    {
        $sessionId = (string) $request->session()->getId();
        if ($sessionId === '') {
            abort(404);
        }

        $otpEnabled = (bool) config('security-defense.dashboard.otp.enabled', false);

        if (! $otpEnabled) {
            return new Response('', 302, ['Location' => '/' . $this->capability->issue($sessionId)]);
        }

        // Fail-closed: no channel = no entry.
        if (! $this->otpDispatcher->canSend()) {
            abort(403, 'Dashboard OTP channel is not configured. Access denied.');
        }

        $clientIp = ClientIpResolver::resolve(
            $request,
            (array) config('security-defense.dashboard.trusted_proxies', ['127.0.0.1', '::1'])
        );

        // Burst limiter: attacker cannot exhaust the email/Telegram rate limit.
        // Reserve the slot atomically so concurrent requests cannot all pass a
        // read-then-write check and overshoot the per-IP quota.
        if (! $this->otpService->acquireRequestSlot($clientIp)) {
            abort(429, 'Too many authorization code requests. Please wait before retrying.');
        }

        // IP + session binding prevents code re-use from a different address.
        $binding = $sessionId . '_' . $clientIp;

        $code = $this->otpService->generate($binding);

        $delivered = $this->otpDispatcher->send($code);

        if (! $delivered) {
            // Discard so an undelivered code is not left guessable. The burst
            // slot is still consumed (it was already reserved atomically):
            // a failing transport must not become a free retry loop.
            $this->otpService->discard($binding);
            abort(503, 'Failed to deliver the authorization code. Please retry.');
        }

        $request->session()->put('security-defense.otp-pending', true);

        return redirect()->route('security-defense.portal.otp-form');
    }

    /**
     * Display the one-time code input form.
     */
    public function codeForm(Request $request): View|RedirectResponse
    {
        if (! $request->session()->get('security-defense.otp-pending', false)) {
            return redirect()->route('security-defense.portal.index');
        }

        return view('security-defense::portal-code');
    }

    /**
     * Verify the submitted one-time code.
     */
    public function verifyCode(Request $request): Response|RedirectResponse
    {
        if (! $request->session()->get('security-defense.otp-pending', false)) {
            return redirect()->route('security-defense.portal.index');
        }

        $sessionId = (string) $request->session()->getId();
        $clientIp = ClientIpResolver::resolve(
            $request,
            (array) config('security-defense.dashboard.trusted_proxies', ['127.0.0.1', '::1'])
        );
        $binding = $sessionId . '_' . $clientIp;

        $input = strtoupper(trim((string) $request->input('otp_code', '')));

        // Length + charset guard.
        if (! preg_match('/^[A-Z0-9]{8}$/', $input)) {
            return $this->codeError('Invalid code format. Enter the 8-character code exactly as received.');
        }

        if (! $this->otpService->verify($binding, $input)) {
            $stillActive = $this->otpService->hasActivePendingCode($binding);
            $msg = $stillActive
                ? 'Incorrect code. Please try again.'
                : 'Code expired or invalidated after too many attempts. Request a new code.';

            return $this->codeError($msg);
        }

        $request->session()->forget('security-defense.otp-pending');

        return new Response('', 302, ['Location' => '/' . $this->capability->issue($sessionId)]);
    }

    private function codeError(string $message): RedirectResponse
    {
        return redirect()
            ->route('security-defense.portal.otp-form')
            ->with('otp_error', $message);
    }
}
