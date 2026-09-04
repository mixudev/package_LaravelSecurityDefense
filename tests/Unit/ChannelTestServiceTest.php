<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Mail;
use InvalidArgumentException;
use Mixudev\SecurityDefense\Services\ChannelTestService;
use Mixudev\SecurityDefense\Tests\TestCase;

class ChannelTestServiceTest extends TestCase
{
    public function test_channel_test_rejects_unwhitelisted_channel(): void
    {
        $service = app(ChannelTestService::class);

        $this->expectException(InvalidArgumentException::class);
        $service->testChannel('malicious_channel_exploit');
    }

    public function test_channel_test_reports_disabled_channel(): void
    {
        config()->set('security-defense.alerts.webhook.enabled', false);

        $service = app(ChannelTestService::class);
        $result = $service->testChannel('webhook');

        $this->assertSame('webhook', $result['channel']);
        $this->assertFalse($result['success']);
        $this->assertFalse($result['enabled']);
        $this->assertStringContainsString('disabled', $result['message']);
    }

    public function test_channel_test_reports_unconfigured_channel(): void
    {
        config()->set('security-defense.alerts.webhook.enabled', true);
        config()->set('security-defense.alerts.webhook.url', null);

        $service = app(ChannelTestService::class);
        $result = $service->testChannel('webhook');

        $this->assertSame('webhook', $result['channel']);
        $this->assertFalse($result['success']);
        $this->assertTrue($result['enabled']);
        $this->assertFalse($result['configured']);
        $this->assertStringContainsString('missing required credentials', $result['message']);
    }

    public function test_channel_test_executes_webhook_probe_successfully(): void
    {
        Http::fake([
            'https://siem.corp.internal/hooks/*' => Http::response(['status' => 'received'], 200),
        ]);

        config()->set('security-defense.alerts.webhook.enabled', true);
        config()->set('security-defense.alerts.webhook.url', 'https://siem.corp.internal/hooks/alerts');

        $service = app(ChannelTestService::class);
        $result = $service->testChannel('webhook');

        $this->assertSame('webhook', $result['channel']);
        $this->assertTrue($result['success']);
        $this->assertTrue($result['enabled']);
        $this->assertTrue($result['configured']);
        $this->assertArrayHasKey('latency_ms', $result);
        $this->assertStringContainsString('delivered successfully', $result['message']);
    }

    public function test_channel_test_executes_mail_probe_successfully(): void
    {
        Mail::fake();

        config()->set('security-defense.alerts.mail.enabled', true);
        config()->set('security-defense.alerts.mail.to', 'alerts@company.test');

        $service = app(ChannelTestService::class);
        $result = $service->testChannel('mail');

        $this->assertSame('mail', $result['channel']);
        $this->assertTrue($result['success']);
        $this->assertTrue($result['enabled']);
        $this->assertTrue($result['configured']);
    }

    public function test_test_all_returns_results_for_all_channels(): void
    {
        $service = app(ChannelTestService::class);
        $results = $service->testAll();

        $this->assertArrayHasKey('webhook', $results);
        $this->assertArrayHasKey('discord', $results);
        $this->assertArrayHasKey('telegram', $results);
        $this->assertArrayHasKey('mail', $results);
        $this->assertArrayHasKey('database', $results);
    }

    public function test_get_channels_status_masks_sensitive_urls(): void
    {
        config()->set('security-defense.alerts.discord.webhook_url', 'https://discord.com/api/webhooks/1234567890/token_secret_abcdef123456');

        $service = app(ChannelTestService::class);
        $statuses = $service->getChannelsStatus();

        $this->assertArrayHasKey('discord', $statuses);
        $this->assertStringContainsString('...', $statuses['discord']['target']);
    }
}
