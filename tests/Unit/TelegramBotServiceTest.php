<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Illuminate\Support\Facades\Http;
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Models\SecurityQuarantine;
use Mixudev\SecurityDefense\Services\TelegramBotService;
use Mixudev\SecurityDefense\Tests\TestCase;

class TelegramBotServiceTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('security-defense.alerts.telegram.enabled', true);
        config()->set('security-defense.alerts.telegram.bot_token', 'test-bot-token-123');
        config()->set('security-defense.alerts.telegram.chat_id', '111222333');
        config()->set('security-defense.alerts.telegram.interactive.enabled', true);
    }

    public function test_interactive_enabled_check(): void
    {
        $service = app(TelegramBotService::class);
        $this->assertTrue($service->isInteractiveEnabled());

        config()->set('security-defense.alerts.telegram.enabled', false);
        $this->assertFalse($service->isInteractiveEnabled());

        config()->set('security-defense.alerts.telegram.enabled', true);
        config()->set('security-defense.alerts.telegram.bot_token', null);
        $this->assertFalse($service->isInteractiveEnabled());
    }

    public function test_automatic_webhook_secret_derivation(): void
    {
        $service = app(TelegramBotService::class);
        $secret = $service->getWebhookSecret();

        $this->assertNotNull($secret);
        $this->assertSame(32, strlen($secret));
        $this->assertSame($secret, $service->getWebhookSecret());

        config()->set('security-defense.alerts.telegram.bot_token', null);
        $this->assertNull($service->getWebhookSecret());
    }

    public function test_authorization_check(): void
    {
        $service = app(TelegramBotService::class);

        // Allowed via primary chat_id
        $this->assertTrue($service->isAuthorized('111222333'));
        $this->assertTrue($service->isAuthorized(111222333));

        // Unauthorized
        $this->assertFalse($service->isAuthorized('999888777'));
        $this->assertFalse($service->isAuthorized('555444333'));
        $this->assertFalse($service->isAuthorized(''));
    }

    public function test_build_main_menu(): void
    {
        $service = app(TelegramBotService::class);
        $payload = $service->buildMainMenu();

        $this->assertArrayHasKey('text', $payload);
        $this->assertArrayHasKey('reply_markup', $payload);
        $this->assertStringContainsString('SECURITY DEFENSE CONTROL PANEL', $payload['text']);
        $this->assertArrayHasKey('inline_keyboard', $payload['reply_markup']);

        $buttons = $payload['reply_markup']['inline_keyboard'];
        $this->assertCount(3, $buttons);
        $this->assertSame('[ System Health ]', $buttons[0][0]['text']);
        $this->assertSame('sec_health', $buttons[0][0]['callback_data']);
    }

    public function test_build_health_report(): void
    {
        $service = app(TelegramBotService::class);
        $payload = $service->buildHealthReport();

        $this->assertStringContainsString('SYSTEM HEALTH DIAGNOSTICS', $payload['text']);
        $this->assertStringContainsString('Database:', $payload['text']);
        $this->assertStringContainsString('Cache Store:', $payload['text']);
        $this->assertStringContainsString('Memory Usage:', $payload['text']);

        $buttons = $payload['reply_markup']['inline_keyboard'];
        $this->assertSame('sec_menu', $buttons[0][0]['callback_data']);
        $this->assertSame('sec_health', $buttons[0][1]['callback_data']);
    }

    public function test_build_security_metrics(): void
    {
        SecurityAlert::create([
            'severity' => 'critical',
            'threat_type' => 'sqli',
            'fingerprint' => 'metric-fp-1',
            'status' => 'new',
            'created_at' => now(),
        ]);

        $service = app(TelegramBotService::class);
        $payload = $service->buildSecurityMetrics();

        $this->assertStringContainsString('SECURITY DEFENSE METRICS', $payload['text']);
        $this->assertStringContainsString('Threats Detected (Today):', $payload['text']);
        $this->assertStringContainsString('Critical:', $payload['text']);
        $this->assertStringContainsString('Payload Scanner:', $payload['text']);
    }

    public function test_build_recent_incidents(): void
    {
        SecurityAlert::create([
            'severity' => 'high',
            'threat_type' => 'xss',
            'rule_identifier' => 'payload_injection',
            'fingerprint' => 'incident-fp-1',
            'status' => 'new',
            'metadata' => ['ip' => '10.0.0.1'],
            'created_at' => now(),
        ]);

        $service = app(TelegramBotService::class);
        $payload = $service->buildRecentIncidents();

        $this->assertStringContainsString('RECENT SECURITY INCIDENTS', $payload['text']);
        $this->assertStringContainsString('[HIGH]', $payload['text']);
        $this->assertStringContainsString('Type: `xss`', $payload['text']);
        $this->assertStringContainsString('IP: `10.0.0.1`', $payload['text']);
    }

    public function test_build_quarantine_report(): void
    {
        SecurityQuarantine::create([
            'ip' => '172.16.0.5',
            'jailed_at' => now(),
            'expires_at' => now()->addMinutes(15),
            'reason' => 'Rate limit exceeded',
        ]);

        $service = app(TelegramBotService::class);
        $payload = $service->buildQuarantineReport();

        $this->assertStringContainsString('QUARANTINED IP ADDRESSES', $payload['text']);
        $this->assertStringContainsString('172.16.0.5', $payload['text']);
        $this->assertStringContainsString('Rate limit exceeded', $payload['text']);
    }

    public function test_handle_command_message_from_authorized_user(): void
    {
        Http::fake([
            'api.telegram.org/bot*/sendMessage' => Http::response(['ok' => true], 200),
        ]);

        $service = app(TelegramBotService::class);

        $update = [
            'update_id' => 1001,
            'message' => [
                'message_id' => 50,
                'chat' => ['id' => 111222333],
                'text' => '/health',
            ],
        ];

        $handled = $service->handleUpdate($update);
        $this->assertTrue($handled);

        Http::assertSent(function ($request) {
            return str_contains($request->url(), 'sendMessage')
                && $request['chat_id'] == '111222333'
                && str_contains($request['text'], 'SYSTEM HEALTH DIAGNOSTICS');
        });
    }

    public function test_handle_command_message_from_unauthorized_user_denied(): void
    {
        Http::fake([
            'api.telegram.org/bot*/sendMessage' => Http::response(['ok' => true], 200),
        ]);

        $service = app(TelegramBotService::class);

        $update = [
            'update_id' => 1002,
            'message' => [
                'message_id' => 51,
                'chat' => ['id' => 999999999], // Unauthorized chat ID
                'text' => '/metrics',
            ],
        ];

        $handled = $service->handleUpdate($update);
        $this->assertFalse($handled);

        Http::assertSent(function ($request) {
            return str_contains($request->url(), 'sendMessage')
                && $request['chat_id'] == '999999999'
                && str_contains($request['text'], 'Access Denied');
        });
    }

    public function test_handle_callback_query(): void
    {
        Http::fake([
            'api.telegram.org/bot*/answerCallbackQuery' => Http::response(['ok' => true], 200),
            'api.telegram.org/bot*/editMessageText' => Http::response(['ok' => true], 200),
        ]);

        $service = app(TelegramBotService::class);

        $update = [
            'update_id' => 1003,
            'callback_query' => [
                'id' => 'cb-12345',
                'data' => 'sec_metrics',
                'from' => ['id' => 111222333, 'username' => 'sec_admin'],
                'message' => [
                    'message_id' => 99,
                    'chat' => ['id' => 111222333],
                ],
            ],
        ];

        $handled = $service->handleUpdate($update);
        $this->assertTrue($handled);

        Http::assertSent(function ($request) {
            return str_contains($request->url(), 'answerCallbackQuery')
                && $request['callback_query_id'] === 'cb-12345';
        });

        Http::assertSent(function ($request) {
            return str_contains($request->url(), 'editMessageText')
                && $request['message_id'] == 99
                && str_contains($request['text'], 'SECURITY DEFENSE METRICS');
        });
    }
}
