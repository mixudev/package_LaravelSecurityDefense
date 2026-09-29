<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Support\Facades\Config;
use Mixudev\SecurityDefense\DTO\SecurityThreat;
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Services\DashboardOtpService;
use Mixudev\SecurityDefense\Tests\TestCase;

final class DashboardOtpBruteForceAlertTest extends TestCase
{
    private const FIXED_SESSION_ID = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

    protected function setUp(): void
    {
        parent::setUp();
        Config::set('security-defense.dashboard.otp.max_attempts', 2);
        Config::set('security-defense.dashboard.otp.alert_on_brute_force', true);
    }

    public function test_reaching_the_attempt_ceiling_persists_a_security_alert(): void
    {
        // Drive the container-resolved service so the provider's
        // resolving() wiring is what is under test, not a local callback.
        $service = $this->app->make(DashboardOtpService::class);
        $binding = self::FIXED_SESSION_ID . '_10.10.10.10';

        $service->generate($binding);
        $service->verify($binding, 'WRONG001');
        $this->assertSame(0, SecurityAlert::query()->count());

        $service->verify($binding, 'WRONG002');

        $alert = SecurityAlert::query()
            ->where('threat_type', 'dashboard_otp_brute_force')
            ->first();

        $this->assertNotNull($alert, 'Brute force against the dashboard gate must reach the SIEM.');
        $this->assertSame('high', $alert->severity);
        $this->assertSame('new', $alert->status);
        $this->assertSame('dashboard_otp', $alert->rule_identifier);
        $this->assertSame('10.10.10.10', $alert->metadata['ip']);
    }

    public function test_the_session_id_is_never_stored_in_the_alert_metadata(): void
    {
        $service = $this->app->make(DashboardOtpService::class);
        $binding = self::FIXED_SESSION_ID . '_10.10.10.11';

        $service->generate($binding);
        $service->verify($binding, 'WRONG001');
        $service->verify($binding, 'WRONG002');

        $alert = SecurityAlert::query()->where('threat_type', 'dashboard_otp_brute_force')->firstOrFail();

        $serialized = (string) json_encode($alert->metadata);
        $this->assertStringNotContainsString(self::FIXED_SESSION_ID, $serialized);
        $this->assertSame(substr(hash('sha256', self::FIXED_SESSION_ID), 0, 16), $alert->metadata['session_ref']);
    }

    public function test_the_plaintext_code_never_reaches_the_alert_metadata(): void
    {
        $service = $this->app->make(DashboardOtpService::class);
        $binding = self::FIXED_SESSION_ID . '_10.10.10.12';

        $code = $service->generate($binding);
        $service->verify($binding, 'WRONG001');
        $service->verify($binding, 'WRONG002');

        $alert = SecurityAlert::query()->where('threat_type', 'dashboard_otp_brute_force')->firstOrFail();
        $this->assertStringNotContainsString($code, (string) json_encode($alert->metadata));
    }
}
