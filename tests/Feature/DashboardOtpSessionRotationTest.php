<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Mail;
use Mixudev\SecurityDefense\Tests\TestCase;

/**
 * Regression: `PortalController::verifyCode()` read the session id and issued the
 * dashboard capability from it WITHOUT rotating the session first.
 *
 * Because the opaque dashboard path is a pure function of the session id, an
 * attacker who planted a known session cookie (subdomain cookie injection, XSS
 * on a sibling host, or a leaked cookie) held a cookie that became a fully
 * authorized dashboard session the moment the victim completed OTP verification.
 * The privilege boundary raised the value of the planted id instead of
 * discarding it.
 *
 * `verifyCode()` now calls `session()->regenerate()` before issuing the
 * capability, so the issued path is derived from a session id the attacker never
 * knew.
 */
final class DashboardOtpSessionRotationTest extends TestCase
{
    private const PLANTED_SESSION_ID = 'dddddddddddddddddddddddddddddddddddddddd';

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('app.key', 'base64:7VzK9gG2e+x8UfXoN9uC7x/2j6yD8Hw0Z1A2B3C4D5E=');
        $app['env'] = 'local';
        $app['config']->set('security-defense.dashboard.opaque_path.enabled', true);
        $app['config']->set('security-defense.dashboard.otp.enabled', true);
        $app['config']->set('security-defense.dashboard.otp.channel', 'email');
        $app['config']->set('security-defense.dashboard.otp.email', 'ops@example.com');
    }

    public function test_otp_verification_issues_a_capability_bound_to_a_fresh_session_id(): void
    {
        Mail::fake();
        $ip = '127.0.0.1';
        $csrf = 'rotation-csrf';
        $code = 'K3Y4B2X9';

        $this->withCookie((string) config('session.cookie'), self::PLANTED_SESSION_ID)
            ->withSession(['_token' => $csrf])
            ->withServerVariables(['REMOTE_ADDR' => $ip])
            ->post(route('security-defense.portal.enter'), ['_token' => $csrf]);

        // The code enter() issued is bound to the planted session id, so seed it.
        Cache::put(
            'dashboard-otp:' . hash('sha256', self::PLANTED_SESSION_ID . '_' . $ip),
            hash('sha256', $code),
            300
        );

        $response = $this->withSession(['_token' => $csrf, 'security-defense.otp-pending' => true])
            ->withServerVariables(['REMOTE_ADDR' => $ip])
            ->post(route('security-defense.portal.verify-otp'), ['_token' => $csrf, 'otp_code' => $code]);

        $response->assertRedirect();

        $issuedPath = basename((string) $response->headers->get('Location'));
        $this->assertMatchesRegularExpression('#^[A-Za-z0-9_-]{64,160}$#', $issuedPath);

        $currentSessionId = (string) $this->app['session']->getId();

        self::assertNotSame(
            self::PLANTED_SESSION_ID,
            $currentSessionId,
            'verifyCode() did not rotate the session id, so the planted id stays valid'
        );

        // The security property: the capability granted to the rotating session
        // must not be reachable with the attacker's pre-planted cookie.
        $attackerAttempt = $this->withSession([
            'security-defense.dashboard-authorized'   => true,
            'security-defense.dashboard-session-path' => $issuedPath,
            '_token'                                  => $csrf,
        ])
            ->withCookie((string) config('session.cookie'), self::PLANTED_SESSION_ID)
            ->withServerVariables(['REMOTE_ADDR' => $ip])
            ->get('/' . $issuedPath);

        $attackerAttempt->assertNotFound();
    }
}
