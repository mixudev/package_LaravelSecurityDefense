<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Support\DiscordAlertFormatter;
use Mixudev\SecurityDefense\Support\TelegramAlertFormatter;
use Mixudev\SecurityDefense\Tests\TestCase;

class MessageFormatterTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('app.key', 'base64:7VzK9gG2e+x8UfXoN9uC7x/2j6yD8Hw0Z1A2B3C4D5E=');
        $app['config']->set('app.name', 'Test App');
    }

    private function makeAlert(): SecurityAlert
    {
        return new SecurityAlert([
            'severity' => 'critical',
            'threat_type' => 'credential_stuffing',
            'fingerprint' => 'fp-format-1234567890abcdef',
            'status' => 'new',
            'rule_identifier' => 'credential_stuffing',
            'metadata' => ['attacker_ip' => '198.51.100.7'],
        ]);
    }

    public function test_discord_formatter_produces_professional_embed_without_emoji(): void
    {
        $payload = DiscordAlertFormatter::payload($this->makeAlert());

        $this->assertSame('Laravel Security Defense', $payload['username']);
        $this->assertCount(1, $payload['embeds']);

        $embed = $payload['embeds'][0];
        $this->assertSame('Security Threat Detected', $embed['title']);
        $this->assertSame(15158332, $embed['color']); // critical red
        $this->assertStringNotContainsString('🛡️', $embed['title']);

        $names = array_column($embed['fields'], 'name');
        $this->assertContains('Threat Type', $names);
        $this->assertContains('Severity', $names);
        $this->assertContains('Sanitized Telemetry', $names);
        // internal diagnostic keys stripped from public metadata
        $this->assertStringNotContainsString('_is_test', json_encode($embed['fields']));
    }

    public function test_discord_formatter_handles_connectivity_test_probe(): void
    {
        $alert = $this->makeAlert();
        $alert->severity = 'low';
        $alert->metadata = [
            '_is_test' => true,
            'source' => 'security_defense_testing_suite',
            'channel' => 'discord',
        ];

        $payload = DiscordAlertFormatter::payload($alert);
        $this->assertSame('Channel Connectivity Test', $payload['embeds'][0]['title']);
        $this->assertSame(3447003, $payload['embeds'][0]['color']); // low blue
    }

    public function test_telegram_formatter_produces_professional_markdown_without_emoji(): void
    {
        $message = TelegramAlertFormatter::message($this->makeAlert());

        $this->assertStringContainsString('[CRITICAL]', $message);
        $this->assertStringContainsString('Security Threat Detected', $message);
        $this->assertStringContainsString('credential_stuffing', $message);
        $this->assertStringContainsString('198.51.100.7', $message);
        $this->assertStringNotContainsString('🚨', $message);
        $this->assertStringNotContainsString('⚠️', $message);
    }

    public function test_telegram_dynamic_fields_escape_markdown_controls(): void
    {
        $alert = $this->makeAlert();
        $alert->threat_type = 'bad_*_[link]';
        $alert->rule_identifier = 'rule`\nInjected';

        $message = TelegramAlertFormatter::message($alert);

        // Values inside code spans stay literal; only span-closing backticks
        // and structural newlines are defanged.
        $this->assertStringContainsString('bad_*_[link]', $message);
        $this->assertStringNotContainsString('bad`', $message);
        $this->assertStringNotContainsString('rule`', $message);
        $this->assertStringNotContainsString("\nInjected", $message);
    }
}
