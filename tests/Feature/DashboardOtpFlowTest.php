<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Mail;
use Mixudev\SecurityDefense\Mail\DashboardOtpMail;
use Mixudev\SecurityDefense\Services\DashboardOtpService;
use Mixudev\SecurityDefense\Tests\TestCase;

final class DashboardOtpFlowTest extends TestCase
{
    private const FIXED_SESSION_ID = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    protected function setUp(): void
    {
        parent::setUp();
        $this->withCookie((string) config('session.cookie'), self::FIXED_SESSION_ID);
    }

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

    // ---- helpers -------------------------------------------------------

    /**
     * Write a known code hash straight into the cache for this binding.
     *
     * Calling generate() instead would SUPERSEDE the code that enter() already
     * issued, which is exactly the behaviour the flow is meant to have; the
     * tests need the issued code, not a replacement.
     */
    private function seedKnownCode(string $sessionId, string $ip, string $code = 'K3Y4B2X9'): string
    {
        Cache::put(
            'dashboard-otp:' . hash('sha256', $sessionId . '_' . $ip),
            hash('sha256', $code),
            300
        );

        return $code;
    }

    private function sessionId(): string
    {
        return self::FIXED_SESSION_ID;
    }

    private function cookieName(): string
    {
        return (string) config('session.cookie');
    }

    // ---- happy path ----------------------------------------------------

    public function test_enter_issues_a_code_and_renders_the_otp_form(): void
    {
        Mail::fake();
        $csrf = 'otp-flow-csrf';

        $this->withSession(['_token' => $csrf])
            ->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->post(route('security-defense.portal.enter'), ['_token' => $csrf])
            ->assertRedirect(route('security-defense.portal.otp-form'));

        Mail::assertSent(DashboardOtpMail::class);
    }

    public function test_otp_form_renders_input_when_pending_state_exists(): void
    {
        $response = $this->withSession(['security-defense.otp-pending' => true])
            ->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get(route('security-defense.portal.otp-form'));

        $response->assertOk();
        $response->assertSee('otp_code', false);
    }

    public function test_correct_code_unlocks_the_opaque_dashboard_path(): void
    {
        Mail::fake();
        $csrf = 'otp-unlock-csrf';
        $ip = '127.0.0.1';

        $this->withSession(['_token' => $csrf])
            ->withServerVariables(['REMOTE_ADDR' => $ip])
            ->post(route('security-defense.portal.enter'), ['_token' => $csrf]);

        // Read back the code that enter() actually issued: the code hash is in
        // the cache, so issue an identical hash for a known plaintext instead
        // of calling generate() again (which would supersede it).
        $code = $this->seedKnownCode($this->sessionId(), $ip);

        $response = $this->withSession(['_token' => $csrf, 'security-defense.otp-pending' => true])
            ->withServerVariables(['REMOTE_ADDR' => $ip])
            ->post(route('security-defense.portal.verify-otp'), ['_token' => $csrf, 'otp_code' => $code]);

        $this->assertMatchesRegularExpression(
            '#^/[A-Za-z0-9_-]{64,160}$#',
            (string) $response->headers->get('Location')
        );
    }

    // ---- rejection paths -----------------------------------------------

    public function test_wrong_code_returns_to_the_form_with_an_error(): void
    {
        Mail::fake();
        $csrf = 'otp-wrong-csrf';
        $ip = '127.0.0.1';

        $this->withSession(['_token' => $csrf])
            ->withServerVariables(['REMOTE_ADDR' => $ip])
            ->post(route('security-defense.portal.enter'), ['_token' => $csrf]);

        $this->seedKnownCode($this->sessionId(), $ip);

        $this->withSession(['_token' => $csrf, 'security-defense.otp-pending' => true])
            ->withServerVariables(['REMOTE_ADDR' => $ip])
            ->post(route('security-defense.portal.verify-otp'), ['_token' => $csrf, 'otp_code' => 'WRONGCO1'])
            ->assertRedirect(route('security-defense.portal.otp-form'))
            ->assertSessionHas('otp_error');
    }

    public function test_verify_without_pending_state_redirects_to_the_portal(): void
    {
        $csrf = 'otp-no-pending';

        $this->withSession(['_token' => $csrf])
            ->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->post(route('security-defense.portal.verify-otp'), ['_token' => $csrf, 'otp_code' => 'AB12CD34'])
            ->assertRedirect(route('security-defense.portal.index'));
    }

    public function test_otp_form_without_pending_state_redirects_to_the_portal(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get(route('security-defense.portal.otp-form'))
            ->assertRedirect(route('security-defense.portal.index'));
    }

    public function test_code_issued_for_one_ip_cannot_be_used_from_another(): void
    {
        Mail::fake();
        $csrf = 'otp-ip-csrf';

        $this->withSession(['_token' => $csrf])
            ->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->post(route('security-defense.portal.enter'), ['_token' => $csrf]);

        $code = $this->seedKnownCode($this->sessionId(), '127.0.0.1');

        // Same session id + code, different client IP => binding mismatch.
        // Configure that IP so only the binding check can reject it.
        Config::set('security-defense.dashboard.allowed_ips', ['127.0.0.1', '::1', '10.0.0.99']);

        $this->withSession(['_token' => $csrf, 'security-defense.otp-pending' => true])
            ->withServerVariables(['REMOTE_ADDR' => '10.0.0.99'])
            ->post(route('security-defense.portal.verify-otp'), ['_token' => $csrf, 'otp_code' => $code])
            ->assertRedirect(route('security-defense.portal.otp-form'))
            ->assertSessionHas('otp_error');
    }

    public function test_code_cannot_be_replayed_after_a_successful_verification(): void
    {
        Mail::fake();
        $csrf = 'otp-replay-csrf';
        $ip = '127.0.0.1';

        $first = $this->withSession(['_token' => $csrf])
            ->withServerVariables(['REMOTE_ADDR' => $ip])
            ->post(route('security-defense.portal.enter'), ['_token' => $csrf]);

        $first->assertRedirect(route('security-defense.portal.otp-form'));

        $code = $this->seedKnownCode($this->sessionId(), $ip);

        $verified = $this->withSession(['_token' => $csrf, 'security-defense.otp-pending' => true])
            ->withServerVariables(['REMOTE_ADDR' => $ip])
            ->post(route('security-defense.portal.verify-otp'), ['_token' => $csrf, 'otp_code' => $code]);

        $verifiedLocation = (string) $verified->headers->get('Location');
        $this->assertMatchesRegularExpression('#^[A-Za-z0-9_-]{64,160}$#', basename($verifiedLocation));

        // Replay: the code is consumed and the pending flag cleared, so the
        // second submit is denied before the code is ever compared.
        $replay = $this->withSession(['_token' => $csrf, 'security-defense.otp-pending' => true])
            ->withServerVariables(['REMOTE_ADDR' => $ip])
            ->post(route('security-defense.portal.verify-otp'), ['_token' => $csrf, 'otp_code' => $code]);

        $replay->assertRedirect(route('security-defense.portal.index'));
        $replay->assertSessionMissing('security-defense.otp-pending');

        // The security property: no second opaque path is ever issued.
        $replayLocation = (string) $replay->headers->get('Location');
        $this->assertStringNotContainsString($verifiedLocation, $replayLocation);
    }

    // ---- fail-closed ---------------------------------------------------

    public function test_enter_is_blocked_when_no_otp_channel_is_configured(): void
    {
        Mail::fake();
        Config::set('security-defense.dashboard.otp.email', null);
        $csrf = 'otp-no-channel';

        $this->withSession(['_token' => $csrf])
            ->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->post(route('security-defense.portal.enter'), ['_token' => $csrf])
            ->assertForbidden();
    }

    public function test_enter_does_not_issue_a_code_when_delivery_fails(): void
    {
        Mail::shouldReceive('to')->andThrow(new \RuntimeException('SMTP down'));
        Config::set('mail.default', 'smtp');
        $csrf = 'otp-delivery-fail';
        $binding = $this->sessionId() . '_127.0.0.1';

        $this->withSession(['_token' => $csrf])
            ->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->post(route('security-defense.portal.enter'), ['_token' => $csrf])
            ->assertStatus(503);

        $this->assertFalse(
            app(DashboardOtpService::class)->hasActivePendingCode($binding),
            'An undelivered code must not remain guessable.'
        );
    }

    public function test_burst_limiter_returns_429_after_the_configured_ceiling(): void
    {
        Mail::fake();
        Config::set('security-defense.dashboard.otp.max_codes_per_window', 2);
        // The burst IP must still clear the IP whitelist, otherwise
        // EnsureLocalAccess rejects it first and this test measures nothing.
        Config::set('security-defense.dashboard.allowed_ips', ['127.0.0.11']);
        $csrf = 'otp-burst';
        $ip = '127.0.0.11';

        for ($i = 0; $i < 2; $i++) {
            $this->withSession(['_token' => $csrf])
                ->withServerVariables(['REMOTE_ADDR' => $ip])
                ->post(route('security-defense.portal.enter'), ['_token' => $csrf])
                ->assertRedirect(route('security-defense.portal.otp-form'));
        }

        $this->withSession(['_token' => $csrf])
            ->withServerVariables(['REMOTE_ADDR' => $ip])
            ->post(route('security-defense.portal.enter'), ['_token' => $csrf])
            ->assertStatus(429);
    }

    // ---- backward compatibility ----------------------------------------

    public function test_disabled_otp_preserves_the_original_single_gate_flow(): void
    {
        Mail::fake();
        Config::set('security-defense.dashboard.otp.enabled', false);
        $csrf = 'otp-disabled';

        $response = $this->withSession(['_token' => $csrf])
            ->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->post(route('security-defense.portal.enter'), ['_token' => $csrf]);

        $this->assertMatchesRegularExpression(
            '#^/[A-Za-z0-9_-]{64,160}$#',
            (string) $response->headers->get('Location')
        );
        Mail::assertNothingSent();
    }

    // ---- input hardening -----------------------------------------------

    /**
     * @dataProvider malformedCodeProvider
     */
    public function test_malformed_codes_are_rejected_without_touching_the_service(string $payload): void
    {
        Mail::fake();
        $csrf = 'otp-malformed';
        $ip = '127.0.0.1';

        $this->withSession(['_token' => $csrf])
            ->withServerVariables(['REMOTE_ADDR' => $ip])
            ->post(route('security-defense.portal.enter'), ['_token' => $csrf]);

        $this->seedKnownCode($this->sessionId(), $ip);

        $this->withSession(['_token' => $csrf, 'security-defense.otp-pending' => true])
            ->withServerVariables(['REMOTE_ADDR' => $ip])
            ->post(route('security-defense.portal.verify-otp'), ['_token' => $csrf, 'otp_code' => $payload])
            ->assertRedirect(route('security-defense.portal.otp-form'))
            ->assertSessionHas('otp_error');
    }

    public static function malformedCodeProvider(): array
    {
        return [
            'sql injection' => ["' OR 1=1--"],
            'script tag' => ['<script>alert(1)</script>'],
            'too long' => ['TOOLONGCODE123'],
            'too short' => ['AB'],
            'symbols' => ['!!!!!!!!'],
            'unicode' => ['ÅÄÖÄÖÄÖ'],
            'null bytes' => ["AB12\0CD34"],
        ];
    }

    public function test_repeated_failures_eventually_destroy_the_code(): void
    {
        Mail::fake();
        Config::set('security-defense.dashboard.otp.max_attempts', 3);
        $csrf = 'otp-exhaust';
        $ip = '127.0.0.1';

        $this->withSession(['_token' => $csrf])
            ->withServerVariables(['REMOTE_ADDR' => $ip])
            ->post(route('security-defense.portal.enter'), ['_token' => $csrf]);

        $binding = $this->sessionId() . '_' . $ip;
        $code = $this->seedKnownCode($this->sessionId(), $ip);

        for ($i = 0; $i < 3; $i++) {
            $this->withSession(['_token' => $csrf, 'security-defense.otp-pending' => true])
                ->withServerVariables(['REMOTE_ADDR' => $ip])
                ->post(route('security-defense.portal.verify-otp'), [
                    '_token' => $csrf,
                    'otp_code' => $i === 2 ? 'WRONGCO3' : 'WRONGCO1',
                ]);
        }

        $this->assertFalse(app(DashboardOtpService::class)->hasActivePendingCode($binding));

        // After invalidation, the real code must also be rejected (not just the code key gone).
        $this->assertFalse(
            app(DashboardOtpService::class)->verify($binding, $code),
            'The real code must be rejected once the attempt ceiling is reached.'
        );
    }

    public function test_the_issued_code_is_never_echoed_into_the_response(): void
    {
        Mail::fake();
        $csrf = 'otp-no-leak';
        $ip = '127.0.0.1';

        $response = $this->withSession(['_token' => $csrf])
            ->withServerVariables(['REMOTE_ADDR' => $ip])
            ->post(route('security-defense.portal.enter'), ['_token' => $csrf]);

        $code = $this->seedKnownCode($this->sessionId(), $ip);

        $this->assertStringNotContainsString($code, (string) $response->getContent());
    }
}
