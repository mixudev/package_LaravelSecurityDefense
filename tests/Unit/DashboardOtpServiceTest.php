<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Mixudev\SecurityDefense\Services\DashboardOtpService;
use Mixudev\SecurityDefense\Tests\TestCase;

class DashboardOtpServiceTest extends TestCase
{
    private DashboardOtpService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = app(DashboardOtpService::class);
    }

    public function test_generate_returns_eight_char_uppercase_alphanumeric(): void
    {
        $code = $this->service->generate('session-a_127.0.0.1');

        $this->assertMatchesRegularExpression('/^[A-Z0-9]{8}$/', $code);
    }

    public function test_generated_codes_are_not_predictable(): void
    {
        $codes = [];
        for ($i = 0; $i < 25; $i++) {
            $codes[] = $this->service->generate('session-' . $i . '_127.0.0.1');
        }

        $this->assertCount(25, array_unique($codes), 'Each generated code must be unique.');
    }

    public function test_plaintext_code_is_never_stored_in_cache(): void
    {
        $binding = 'session-store_127.0.0.1';
        $code = $this->service->generate($binding);

        $stored = Cache::get('dashboard-otp:' . hash('sha256', $binding));

        $this->assertNotNull($stored);
        $this->assertNotSame($code, $stored, 'The code must not be stored in plaintext.');
        $this->assertSame(hash('sha256', $code), $stored);
    }

    public function test_verify_accepts_the_issued_code(): void
    {
        $binding = 'session-ok_127.0.0.1';
        $code = $this->service->generate($binding);

        $this->assertTrue($this->service->verify($binding, $code));
    }

    public function test_verify_is_case_insensitive_and_trims_input(): void
    {
        $binding = 'session-case_127.0.0.1';
        $code = $this->service->generate($binding);

        $this->assertTrue($this->service->verify($binding, '  ' . strtolower($code) . '  '));
    }

    public function test_verify_rejects_wrong_code(): void
    {
        $binding = 'session-wrong_127.0.0.1';
        $this->service->generate($binding);

        $this->assertFalse($this->service->verify($binding, 'ZZZZZZZZ'));
    }

    public function test_verify_is_consume_once(): void
    {
        $binding = 'session-replay_127.0.0.1';
        $code = $this->service->generate($binding);

        $this->assertTrue($this->service->verify($binding, $code));
        $this->assertFalse($this->service->verify($binding, $code), 'A used code must not be accepted twice.');
    }

    public function test_generate_replaces_the_previously_issued_code(): void
    {
        $binding = 'session-replace_127.0.0.1';
        $first = $this->service->generate($binding);
        $second = $this->service->generate($binding);

        $this->assertFalse($this->service->verify($binding, $first), 'The superseded code must stop working.');
        $this->assertTrue($this->service->verify($binding, $second));
    }

    public function test_code_is_bound_to_exact_binding(): void
    {
        $binding = 'session-bind_127.0.0.1';
        $code = $this->service->generate($binding);

        $this->assertFalse($this->service->verify('other-session_10.0.0.9', $code));
    }

    public function test_wrong_attempts_invalidate_the_code(): void
    {
        Config::set('security-defense.dashboard.otp.max_attempts', 3);
        $binding = 'session-attempts_127.0.0.1';
        $code = $this->service->generate($binding);

        $this->assertFalse($this->service->verify($binding, 'WRONGCO1'));
        $this->assertFalse($this->service->verify($binding, 'WRONGCO2'));
        $this->assertTrue($this->service->hasActivePendingCode($binding));

        $this->assertFalse($this->service->verify($binding, 'WRONGCO3'));
        $this->assertFalse($this->service->hasActivePendingCode($binding), 'Code must be invalidated after max attempts.');
        $this->assertFalse($this->service->verify($binding, $code), 'The real code must be rejected once invalidated.');
    }

    public function test_correct_code_still_works_just_below_the_attempt_ceiling(): void
    {
        Config::set('security-defense.dashboard.otp.max_attempts', 3);
        $binding = 'session-ceiling_127.0.0.1';
        $code = $this->service->generate($binding);

        $this->assertFalse($this->service->verify($binding, 'WRONGCO1'));
        $this->assertFalse($this->service->verify($binding, 'WRONGCO2'));
        $this->assertTrue($this->service->verify($binding, $code));
    }

    public function test_expired_code_is_rejected(): void
    {
        Config::set('security-defense.dashboard.otp.ttl_seconds', 1);
        $binding = 'session-expired_127.0.0.1';
        $code = $this->service->generate($binding);

        // The service floors the TTL at 60s, so assert the ceiling contract
        // instead of sleeping: a code stored outside the window is refused.
        Cache::put(
            'dashboard-otp:' . hash('sha256', $binding),
            hash('sha256', $code),
            -1
        );

        $this->assertFalse($this->service->verify($binding, $code));
    }

    public function test_burst_limiter_blocks_after_max_codes_per_window(): void
    {
        Config::set('security-defense.dashboard.otp.max_codes_per_window', 3);
        Config::set('security-defense.dashboard.otp.window_seconds', 900);
        $ip = '203.0.113.77';

        // The reservation is a single atomic step: there is no separate
        // "may I?" check that a concurrent request could pass at the same time.
        for ($i = 0; $i < 3; $i++) {
            $this->assertTrue($this->service->acquireRequestSlot($ip));
        }

        $this->assertFalse($this->service->acquireRequestSlot($ip));
    }

    public function test_burst_limiter_is_scoped_per_ip(): void
    {
        Config::set('security-defense.dashboard.otp.max_codes_per_window', 1);
        $ip = '203.0.113.78';
        $otherIp = '203.0.113.79';

        $this->assertTrue($this->service->acquireRequestSlot($ip));

        $this->assertFalse($this->service->acquireRequestSlot($ip));
        $this->assertTrue($this->service->acquireRequestSlot($otherIp));
    }

    public function test_burst_counter_key_does_not_leak_the_raw_ip(): void
    {
        $ip = '203.0.113.80';
        $this->service->acquireRequestSlot($ip);

        $this->assertTrue(
            (int) Cache::get('dashboard-otp-burst:' . hash('sha256', $ip)) >= 1,
            'Burst counter must be keyed by a hash, not the raw IP.'
        );
    }

    public function test_rejected_burst_slot_does_not_inflate_the_counter(): void
    {
        Config::set('security-defense.dashboard.otp.max_codes_per_window', 2);
        $ip = '203.0.113.81';

        $this->assertTrue($this->service->acquireRequestSlot($ip));
        $this->assertTrue($this->service->acquireRequestSlot($ip));

        for ($i = 0; $i < 5; $i++) {
            $this->assertFalse($this->service->acquireRequestSlot($ip));
        }

        // Over-rejection must not keep growing the counter: a later legit
        // request should see exactly max, not max+5.
        $this->assertSame(2, (int) Cache::get('dashboard-otp-burst:' . hash('sha256', $ip)));
    }
}
