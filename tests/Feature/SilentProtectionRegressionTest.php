<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Mixudev\SecurityDefense\Jobs\ProcessSecurityDataAuditJob;
use Mixudev\SecurityDefense\Mail\SecurityAlertMail;
use Mixudev\SecurityDefense\Middleware\AuthenticatedSessionScanner;
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Contracts\ThreatSource;
use Mixudev\SecurityDefense\Services\SecurityDefenseManager;
use Mixudev\SecurityDefense\Support\RequestLocationRedactor;
use Mixudev\SecurityDefense\Tests\TestCase;
use Symfony\Component\HttpFoundation\Response;

/**
 * Regression suite for audit findings that are NOT payload detection:
 *
 *  1. AuthenticatedSessionScanner swallowed the abort(403) it issued itself,
 *     because HttpException implements Throwable and the guard was a
 *     catch-all. block_on_hijack=true never blocked anything.
 *  2. ProcessSecurityDataAuditJob caught Throwable without rethrowing, so the
 *     queue considered the job done: no retry, no failed_jobs entry.
 *  3. SecurityAlertMail rendered raw metadata, relying purely on the model
 *     mutator for sanitisation.
 *  4. RequestLocationRedactor only redacted resolved dashboard routes, so an
 *     unresolved request leaked the opaque path segment verbatim.
 */
class SilentProtectionRegressionTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('app.key', 'base64:7VzK9gG2e+x8UfXoN9uC7x/2j6yD8Hw0Z1A2B3C4D5E=');
    }

    /**
     * block_on_hijack must actually deny the request. A fake manager returning a
     * critical hijack threat stands in for the real detection path.
     */
    public function test_block_on_hijack_returns_403_and_does_not_reach_controller(): void
    {
        config()->set('security-defense.session_intelligence.block_on_hijack', true);

        $threat = new \Mixudev\SecurityDefense\DTO\SecurityThreat(
            severity: 'critical',
            threatType: 'session_hijack_suspected',
            fingerprint: 'probe-hijack-fp',
            metadata: [],
            ruleIdentifier: 'probe'
        );

        $manager = new class($threat) extends SecurityDefenseManager {
            public function __construct(private mixed $stub) {}

            public function record(ThreatSource|array $source): array
            {
                return [$this->stub];
            }
        };

        $user = new class {
            public function getAuthIdentifier(): int
            {
                return 1;
            }
        };

        $request = \Illuminate\Http\Request::create('/account/profile', 'GET');
        $request->setUserResolver(static fn () => $user);
        $request->setLaravelSession($this->app['session']->driver());

        $scanner = new AuthenticatedSessionScanner($manager);
        $reachedController = false;
        $status = null;

        try {
            $scanner->handle($request, function () use (&$reachedController) {
                $reachedController = true;

                return new Response('CONTROLLER REACHED', 200);
            });
        } catch (\Symfony\Component\HttpKernel\Exception\HttpException $e) {
            $status = $e->getStatusCode();
        }

        $this->assertSame(403, $status, 'Hijack kritis harus memblokir dengan 403.');
        $this->assertFalse($reachedController, 'Controller tidak boleh tercapai setelah blokir.');
    }

    /**
     * The audit job must propagate failures so the queue can retry and record
     * the failure. Swallowing makes a dropped audit row indistinguishable from
     * a successful one.
     */
    public function test_audit_job_rethrows_so_queue_records_failure(): void
    {
        // $guarded = ['id'], so an unknown column reaches the INSERT statement
        // and the DB rejects it. That is a deterministic persistence failure.
        config()->set('security-defense.data_audit.table', 'security_data_audits_table_that_does_not_exist');

        $job = new ProcessSecurityDataAuditJob([
            'event' => 'created',
            'auditable_type' => 'App\\Models\\User',
            'auditable_id' => '1',
            'ip_address' => '127.0.0.1',
            'request_method' => 'POST',
            'modified_fields' => ['email'],
            'is_tampered' => false,
        ]);

        // Missing required columns make the insert fail at the DB layer.
        $threw = false;

        try {
            $job->handle(app(\Mixudev\SecurityDefense\Services\DataAuditService::class));
        } catch (\Throwable $e) {
            $threw = true;
        }

        $this->assertTrue(
            $threw,
            'Job audit harus melempar exception agar worker mencatat kegagalan dan me-retry.'
        );
    }

    public function test_alert_email_renders_sanitized_metadata(): void
    {
        $alert = new SecurityAlert([
            'severity' => SecurityAlert::SEVERITY_HIGH,
            'threat_type' => 'brute_force',
            'fingerprint' => 'probe-mail-fp',
            'status' => SecurityAlert::STATUS_NEW,
        ]);

        // Bypass the model mutator the way a raw DB update would.
        $alert->setRawAttributes(array_merge($alert->getAttributes(), [
            'metadata' => json_encode([
                'password' => 'hunter2-plaintext',
                'api_key' => 'sk-live-plaintext',
                'note' => 'Authorization: Bearer abc123plaintext',
            ]),
        ]));

        $html = (new SecurityAlertMail($alert))->render();

        $this->assertStringNotContainsString('hunter2-plaintext', $html, 'Password tidak boleh bocor ke email.');
        $this->assertStringNotContainsString('sk-live-plaintext', $html, 'API key tidak boleh bocor ke email.');
        $this->assertStringNotContainsString('abc123plaintext', $html, 'Token tidak boleh bocor ke email.');
    }

    public function test_redactor_masks_opaque_path_when_route_is_unresolved(): void
    {
        $opaque = str_repeat('a1b2c3d4', 8) . '/a7k2';
        $request = \Illuminate\Http\Request::create('/' . $opaque, 'GET');

        $redacted = RequestLocationRedactor::path($request);

        $this->assertStringNotContainsString(
            str_repeat('a1b2c3d4', 8),
            $redacted,
            'Segmen opaque yang belum ter-resolve tidak boleh bocor ke telemetry.'
        );
        $this->assertStringContainsString('[redacted]', $redacted);
    }

    public function test_redactor_keeps_ordinary_paths_readable(): void
    {
        $request = \Illuminate\Http\Request::create('/store/gaming/nintendo-switch-console', 'GET');

        $redacted = RequestLocationRedactor::path($request);

        $this->assertSame(
            'store/gaming/nintendo-switch-console',
            $redacted,
            'Path umum tidak boleh ikut ter-mask.'
        );
    }
}