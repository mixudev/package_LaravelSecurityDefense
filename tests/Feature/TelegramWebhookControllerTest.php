<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Mixudev\SecurityDefense\Tests\TestCase;

final class TelegramWebhookControllerTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('app.key', 'base64:' . base64_encode(random_bytes(32)));
        $app['config']->set('security-defense.alerts.telegram.enabled', true);
        $app['config']->set('security-defense.alerts.telegram.bot_token', 'test-bot-token-123');
        $app['config']->set('security-defense.alerts.telegram.chat_id', '111222333');
        $app['config']->set('security-defense.alerts.telegram.interactive.enabled', true);
    }

    public function test_webhook_rejects_without_secret_header(): void
    {
        $this->postJson('/security-defense/telegram/webhook', [
            'update_id' => 1,
            'message' => ['text' => 'x'],
        ])->assertStatus(401);
    }

    public function test_webhook_rejects_wrong_secret(): void
    {
        $this->postJson('/security-defense/telegram/webhook', [
            'update_id' => 1,
            'message' => ['text' => 'x'],
        ], ['X-Telegram-Bot-Api-Secret-Token' => 'wrong-secret'])
            ->assertStatus(401);
    }

    public function test_webhook_accepts_correct_secret(): void
    {
        $secret = app(\Mixudev\SecurityDefense\Services\TelegramBotService::class)->getWebhookSecret();

        $this->postJson('/security-defense/telegram/webhook', [
            'update_id' => 999,
            'message' => ['text' => '/start'],
        ], ['X-Telegram-Bot-Api-Secret-Token' => $secret])
            ->assertStatus(200)
            ->assertJson(['ok' => true]);
    }

    public function test_webhook_fails_closed_when_bot_token_missing(): void
    {
        config()->set('security-defense.alerts.telegram.bot_token', null);

        // Missing bot token disables interactive mode entirely → 403.
        // Either way (403 or 401) the payload is never processed.
        $this->postJson('/security-defense/telegram/webhook', [
            'update_id' => 1,
        ], ['X-Telegram-Bot-Api-Secret-Token' => 'anything'])
            ->assertStatus(403);
    }
}