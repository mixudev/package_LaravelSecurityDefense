<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Mixudev\SecurityDefense\DTO\SecurityThreat;
use Mixudev\SecurityDefense\Services\DashboardOtpService;
use Mixudev\SecurityDefense\Tests\TestCase;

final class DashboardOtpHardeningTest extends TestCase
{
    private DashboardOtpService $service;
    private Repository $cache;

    protected function setUp(): void
    {
        parent::setUp();
        $this->cache = new Repository(new ArrayStore());
        $this->service = new DashboardOtpService($this->cache);
    }

    public function test_lock_is_actually_acquired_on_lock_supporting_stores(): void
    {
        $binding = 'sess_127.0.0.1';
        $code = $this->service->generate($binding);

        $this->assertTrue($this->service->verify($binding, $code));
        $this->assertFalse($this->service->hasActivePendingCode($binding));
    }

    public function test_atomic_burst_limiter_rejects_exceeded_slots_atomically(): void
    {
        $ip = '192.168.1.100';
        $this->app['config']->set('security-defense.dashboard.otp.max_codes_per_window', 3);

        $this->assertTrue($this->service->acquireRequestSlot($ip)); // 1
        $this->assertTrue($this->service->acquireRequestSlot($ip)); // 2
        $this->assertTrue($this->service->acquireRequestSlot($ip)); // 3
        $this->assertFalse($this->service->acquireRequestSlot($ip)); // 4 rejected
        $this->assertFalse($this->service->acquireRequestSlot($ip)); // 5 rejected
    }

    public function test_atomic_failure_registration_increments_and_invalidates_at_max(): void
    {
        $binding = 'sess_brute_127.0.0.1';
        $this->app['config']->set('security-defense.dashboard.otp.max_attempts', 3);
        $code = $this->service->generate($binding);

        $this->assertFalse($this->service->verify($binding, 'WRONG001'));
        $this->assertTrue($this->service->hasActivePendingCode($binding));

        $this->assertFalse($this->service->verify($binding, 'WRONG002'));
        $this->assertTrue($this->service->hasActivePendingCode($binding));

        $this->assertFalse($this->service->verify($binding, 'WRONG003'));
        $this->assertFalse($this->service->hasActivePendingCode($binding));
    }

    public function test_brute_force_failure_triggers_alert_callback_with_threat_dto(): void
    {
        $binding = 'session123_10.0.0.5';
        $this->app['config']->set('security-defense.dashboard.otp.max_attempts', 2);
        $this->service->generate($binding);

        /** @var SecurityThreat|null $reportedThreat */
        $reportedThreat = null;
        $this->service->onBruteForce(function (SecurityThreat $threat) use (&$reportedThreat) {
            $reportedThreat = $threat;
        });

        // 1st failure: below threshold
        $this->service->verify($binding, 'WRONG001');
        $this->assertNull($reportedThreat);

        // 2nd failure: threshold reached
        $this->service->verify($binding, 'WRONG002');
        $this->assertInstanceOf(SecurityThreat::class, $reportedThreat);
        $this->assertSame('dashboard_otp_brute_force', $reportedThreat->threatType);
        $this->assertSame('high', $reportedThreat->severity);
        $this->assertSame('10.0.0.5', $reportedThreat->metadata['ip']);
        $this->assertSame(2, $reportedThreat->metadata['attempts']);
    }

    public function test_brute_force_alert_is_deduplicated_per_ip_not_per_session(): void
    {
        $this->app['config']->set('security-defense.dashboard.otp.max_attempts', 1);
        $ip = '10.0.0.9';

        $seen = [];
        $this->service->onBruteForce(function (SecurityThreat $t) use (&$seen) {
            $seen[] = $t->fingerprint;
        });

        $this->service->generate('sessionA_' . $ip);
        $this->service->verify('sessionA_' . $ip, 'WRONG001');

        $this->service->generate('sessionB_' . $ip);
        $this->service->verify('sessionB_' . $ip, 'WRONG001');

        // A new session (e.g. attacker cleared cookies) must NOT mint a new
        // alert identity, or the attacker could flood the SIEM by cycling ids.
        $this->assertCount(2, $seen);
        $this->assertSame($seen[0], $seen[1]);
    }

    public function test_a_failing_reporter_never_propagates_to_the_caller(): void
    {
        $this->app['config']->set('security-defense.dashboard.otp.max_attempts', 1);
        $binding = 'sess_err_10.0.0.20';
        $this->service->generate($binding);

        $this->service->onBruteForce(static function (): void {
            throw new \RuntimeException('alert pipeline down');
        });

        // A broken alert pipeline must not turn a rejected login into a 500.
        $this->assertFalse($this->service->verify($binding, 'WRONG001'));
    }

    public function test_brute_force_alerting_can_be_disabled(): void
    {
        $this->app['config']->set('security-defense.dashboard.otp.max_attempts', 1);
        $this->app['config']->set('security-defense.dashboard.otp.alert_on_brute_force', false);
        $binding = 'sess_off_10.0.0.30';
        $this->service->generate($binding);

        $fired = false;
        $this->service->onBruteForce(function () use (&$fired): void {
            $fired = true;
        });

        $this->service->verify($binding, 'WRONG001');

        $this->assertFalse($fired);
    }
}
