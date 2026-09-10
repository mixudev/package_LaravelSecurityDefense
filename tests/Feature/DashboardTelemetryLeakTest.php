<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Mixudev\SecurityDefense\Middleware\AuthenticatedSessionScanner;
use Mixudev\SecurityDefense\Services\DataAuditService;
use Mixudev\SecurityDefense\Tests\TestCase;

class DashboardTelemetryLeakTest extends TestCase
{
    private const TOKEN = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('app.key', 'base64:' . base64_encode(random_bytes(32)));
        $app['env'] = 'local';
        putenv('SECURITY_DEFENSE_DASHBOARD_PATH=' . self::TOKEN);
    }

    protected function tearDown(): void
    {
        putenv('SECURITY_DEFENSE_DASHBOARD_PATH');
        parent::tearDown();
    }

    public function test_session_scanner_metadata_never_contains_opaque_token(): void
    {
        config()->set('security-defense.session_intelligence.enabled', true);
        config()->set('security-defense.enabled', true);

        $user = new class implements \Illuminate\Contracts\Auth\Authenticatable {
            public function getAuthIdentifierName(): string { return 'id'; }
            public function getAuthIdentifier(): string { return '1'; }
            public function getAuthPassword(): string { return ''; }
            public function getAuthPasswordName(): string { return 'password'; }
            public function getRememberToken(): ?string { return null; }
            public function setRememberToken($value): void {}
            public function getRememberTokenName(): string { return 'remember_token'; }
        };

        Auth::login($user);

        $request = Request::create('/security-defense', 'GET');
        $request->setUserResolver(fn () => $user);
        $request->setRouteResolver(fn () => new class {
            public function getName(): string { return 'security-defense.dashboard'; }
        });

        $captured = [];
        $manager = $this->createMock(\Mixudev\SecurityDefense\Services\SecurityDefenseManager::class);
        $manager->expects(self::once())
            ->method('record')
            ->with(self::callback(function (array $data) use (&$captured): bool {
                $captured = $data;

                return true;
            }))
            ->willReturn([]);

        (new AuthenticatedSessionScanner($manager))->handle($request, fn ($request) => $request);

        $serialized = serialize($captured);
        self::assertStringNotContainsString(self::TOKEN, $serialized, 'Opaque token leaked into session telemetry.');
        self::assertStringContainsString('[dashboard-route:security-defense.dashboard]', $serialized);
    }

    public function test_data_audit_service_request_url_never_contains_opaque_token(): void
    {
        config()->set('security-defense.data_audit.enabled', true);

        $request = Request::create('/' . self::TOKEN, 'GET');
        $request->setRouteResolver(fn () => new class {
            public function getName(): string { return 'security-defense.dashboard'; }
        });

        // Use a real model on the audits table so the audit row is created.
        $probe = \Mixudev\SecurityDefense\Models\SecurityDataAudit::query()->create([
            'event' => 'created',
            'auditable_type' => 'probe',
            'auditable_id' => '42',
        ]);

        $audit = (new DataAuditService($request))->recordMutation($probe, 'created');

        if ($audit !== null) {
            self::assertStringNotContainsString(self::TOKEN, $audit->request_url ?? '');
        } else {
            self::markTestSkipped('Data audit disabled or queue enabled; no audit row created.');
        }
    }
}