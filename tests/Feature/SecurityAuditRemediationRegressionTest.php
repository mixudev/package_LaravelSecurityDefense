<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Mixudev\SecurityDefense\Mail\DashboardOtpMail;
use Mixudev\SecurityDefense\Middleware\AuthenticatedSessionScanner;
use Mixudev\SecurityDefense\Services\AuditPayloadSanitizer;
use Mixudev\SecurityDefense\Services\SecurityDefenseManager;
use Mixudev\SecurityDefense\Tests\TestCase;

final class SecurityAuditRemediationRegressionTest extends TestCase
{
    public function test_oversized_snapshot_preview_respects_byte_limit(): void
    {
        config()->set('security-defense.data_audit.max_payload_snapshot_bytes', 8192);
        $request = Request::create('/submit', 'POST', array_fill_keys(
            array_map(static fn (int $i): string => "field_{$i}", range(1, 10)),
            str_repeat('x', 2000)
        ));

        $snapshot = (new AuditPayloadSanitizer())->resolvePayloadSnapshot($request);

        self::assertNotNull($snapshot);
        self::assertLessThanOrEqual(8192, strlen((string) json_encode($snapshot)));
    }

    public function test_authenticated_session_telemetry_contains_only_one_way_session_hash(): void
    {
        $captured = null;
        $manager = new class($captured) extends SecurityDefenseManager {
            public function __construct(private mixed &$captured) {}

            public function record(\Mixudev\SecurityDefense\Contracts\ThreatSource|array $source): array
            {
                $this->captured = $source;

                return [];
            }
        };
        $request = Request::create('/account', 'GET');
        $request->setUserResolver(static fn () => new class {
            public function getAuthIdentifier(): int { return 7; }
        });
        $request->setLaravelSession($this->app['session']->driver());
        $request->session()->setId('raw-session-secret');

        (new AuthenticatedSessionScanner($manager))->handle($request, static fn () => null);

        $metadata = $captured['metadata'] ?? [];
        self::assertArrayNotHasKey('session_id', $metadata, 'Raw session ID must not enter telemetry.');
        self::assertIsString($metadata['session_hash'] ?? null);
        self::assertSame(64, strlen((string) ($metadata['session_hash'] ?? '')));
        self::assertNotSame('raw-session-secret', $metadata['session_hash'] ?? null);
        self::assertStringNotContainsString(
            'raw-session-secret',
            (string) json_encode($captured)
        );
    }

    public function test_dashboard_otp_mailable_is_encrypted_when_queued(): void
    {
        self::assertInstanceOf(ShouldBeEncrypted::class, new DashboardOtpMail('123456'));
    }
}
