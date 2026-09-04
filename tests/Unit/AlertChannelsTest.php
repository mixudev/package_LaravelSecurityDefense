<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Illuminate\Support\Facades\Http;
use Mixudev\SecurityDefense\Channels\DatabaseChannel;
use Mixudev\SecurityDefense\Channels\DiscordChannel;
use Mixudev\SecurityDefense\Channels\TelegramChannel;
use Mixudev\SecurityDefense\Channels\WebhookChannel;
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Tests\TestCase;

class AlertChannelsTest extends TestCase
{
    public function test_database_channel_persists_alert(): void
    {
        $channel = app(DatabaseChannel::class);

        $alert = new SecurityAlert([
            'severity' => 'high',
            'threat_type' => 'brute_force',
            'fingerprint' => 'test-db-fp',
            'status' => 'new',
            'metadata' => ['target' => 'alice'],
        ]);

        $result = $channel->send($alert);

        $this->assertTrue($result);
        $this->assertDatabaseHas('security_alerts', [
            'fingerprint' => 'test-db-fp',
            'threat_type' => 'brute_force',
        ]);
    }

    public function test_telegram_channel_skips_when_unconfigured(): void
    {
        config()->set('security-defense.alerts.telegram.enabled', false);
        config()->set('security-defense.alerts.telegram.bot_token', null);

        $channel = app(TelegramChannel::class);
        $alert = new SecurityAlert(['fingerprint' => 'fp1']);

        $this->assertFalse($channel->isConfigured());
        $this->assertFalse($channel->send($alert));
    }

    public function test_telegram_channel_dispatches_http_successfully(): void
    {
        config()->set('security-defense.alerts.telegram.enabled', true);
        config()->set('security-defense.alerts.telegram.bot_token', 'mock_token');
        config()->set('security-defense.alerts.telegram.chat_id', '123456');

        $channel = app(TelegramChannel::class);

        $alert = new SecurityAlert([
            'severity' => 'critical',
            'threat_type' => 'payload_injection',
            'fingerprint' => 'fp-telegram',
            'metadata' => ['ip' => '1.1.1.1'],
        ]);

        Http::fake([
            'api.telegram.org/*' => Http::response(['ok' => true], 200),
        ]);

        $this->assertTrue($channel->send($alert));
    }

    public function test_telegram_channel_handles_api_failure_gracefully(): void
    {
        config()->set('security-defense.alerts.telegram.enabled', true);
        config()->set('security-defense.alerts.telegram.bot_token', 'mock_token');
        config()->set('security-defense.alerts.telegram.chat_id', '123456');

        $channel = app(TelegramChannel::class);

        $alert = new SecurityAlert([
            'severity' => 'critical',
            'threat_type' => 'payload_injection',
            'fingerprint' => 'fp-telegram-fail',
            'metadata' => ['ip' => '1.1.1.1'],
        ]);

        Http::fake([
            'api.telegram.org/*' => Http::response(['ok' => false], 500),
        ]);

        $this->assertFalse($channel->send($alert));
    }

    public function test_discord_channel_dispatches_http_successfully(): void
    {
        config()->set('security-defense.alerts.discord.enabled', true);
        config()->set('security-defense.alerts.discord.webhook_url', 'https://discord.com/api/webhooks/123/abc');

        $channel = app(DiscordChannel::class);

        $alert = new SecurityAlert([
            'severity' => 'high',
            'threat_type' => 'credential_stuffing',
            'fingerprint' => 'fp-discord',
            'metadata' => ['ip' => '2.2.2.2'],
        ]);

        Http::fake([
            'discord.com/*' => Http::response([], 204),
        ]);

        $this->assertTrue($channel->send($alert));
    }

    public function test_discord_channel_handles_failure_gracefully(): void
    {
        config()->set('security-defense.alerts.discord.enabled', true);
        config()->set('security-defense.alerts.discord.webhook_url', 'https://discord.com/api/webhooks/123/abc');

        $channel = app(DiscordChannel::class);

        $alert = new SecurityAlert([
            'severity' => 'high',
            'threat_type' => 'credential_stuffing',
            'fingerprint' => 'fp-discord-fail',
            'metadata' => ['ip' => '2.2.2.2'],
        ]);

        Http::fake([
            'discord.com/*' => Http::response(['message' => 'Rate limited'], 429),
        ]);

        $this->assertFalse($channel->send($alert));
    }

    public function test_webhook_channel_sends_signature_header(): void
    {
        config()->set('security-defense.alerts.webhook.enabled', true);
        config()->set('security-defense.alerts.webhook.url', 'https://siem.internal/api/alerts');
        config()->set('security-defense.alerts.webhook.secret', 'my-secret-key');

        $channel = app(WebhookChannel::class);

        $alert = new SecurityAlert([
            'id' => 99,
            'severity' => 'medium',
            'threat_type' => 'rate_limit_bypass',
            'fingerprint' => 'fp-webhook',
            'status' => 'new',
            'metadata' => ['note' => 'test'],
        ]);

        Http::fake([
            'siem.internal/*' => function ($request) {
                $this->assertTrue($request->hasHeader('X-Security-Defense-Signature'));
                return Http::response(['status' => 'received'], 200);
            },
        ]);

        $this->assertTrue($channel->send($alert));
    }
}
