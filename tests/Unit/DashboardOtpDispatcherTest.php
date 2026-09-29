<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Mail;
use Mixudev\SecurityDefense\Mail\DashboardOtpMail;
use Mixudev\SecurityDefense\Services\DashboardOtpDispatcher;
use Mixudev\SecurityDefense\Tests\TestCase;

class DashboardOtpDispatcherTest extends TestCase
{
    public function test_can_send_returns_false_when_no_channel_configured(): void
    {
        Config::set('security-defense.dashboard.otp.channel', null);
        Config::set('security-defense.dashboard.otp.email', null);

        $this->assertFalse(app(DashboardOtpDispatcher::class)->canSend());
    }

    public function test_can_send_returns_false_with_invalid_email_address(): void
    {
        Config::set('security-defense.dashboard.otp.channel', 'email');
        Config::set('security-defense.dashboard.otp.email', 'not-an-email');

        $this->assertFalse(app(DashboardOtpDispatcher::class)->canSend());
    }

    public function test_can_send_returns_true_for_valid_email_channel(): void
    {
        Config::set('security-defense.dashboard.otp.channel', 'email');
        Config::set('security-defense.dashboard.otp.email', 'ops@example.com');

        $this->assertTrue(app(DashboardOtpDispatcher::class)->canSend());
    }

    public function test_can_send_returns_true_for_telegram_channel_when_fully_configured(): void
    {
        Config::set('security-defense.dashboard.otp.channel', 'telegram');
        Config::set('security-defense.alerts.telegram.enabled', true);
        Config::set('security-defense.alerts.telegram.chat_id', '12345678');
        Config::set('security-defense.alerts.telegram.bot_token', 'FAKE:TOKEN');

        $this->assertTrue(app(DashboardOtpDispatcher::class)->canSend());
    }

    public function test_can_send_returns_false_for_telegram_when_bot_token_missing(): void
    {
        Config::set('security-defense.dashboard.otp.channel', 'telegram');
        Config::set('security-defense.alerts.telegram.enabled', true);
        Config::set('security-defense.alerts.telegram.chat_id', '12345678');
        Config::set('security-defense.alerts.telegram.bot_token', null);

        $this->assertFalse(app(DashboardOtpDispatcher::class)->canSend());
    }

    public function test_send_via_email_dispatches_the_otp_mailable(): void
    {
        Mail::fake();
        Config::set('security-defense.dashboard.otp.channel', 'email');
        Config::set('security-defense.dashboard.otp.email', 'ops@example.com');

        $result = app(DashboardOtpDispatcher::class)->send('AB3K9XZ1');

        $this->assertTrue($result);
        Mail::assertSent(DashboardOtpMail::class, function (DashboardOtpMail $mail): bool {
            return $mail->hasTo('ops@example.com');
        });
    }

    public function test_send_returns_false_when_channel_not_configured(): void
    {
        Config::set('security-defense.dashboard.otp.channel', null);

        $this->assertFalse(app(DashboardOtpDispatcher::class)->send('AB3K9XZ1'));
    }

    public function test_send_via_telegram_calls_telegram_api(): void
    {
        Http::fake(['api.telegram.org/*' => Http::response(['ok' => true], 200)]);
        Config::set('security-defense.dashboard.otp.channel', 'telegram');
        Config::set('security-defense.alerts.telegram.enabled', true);
        Config::set('security-defense.alerts.telegram.chat_id', '99887766');
        Config::set('security-defense.alerts.telegram.bot_token', 'FAKE:TOKEN');

        $result = app(DashboardOtpDispatcher::class)->send('XZ12ABCD');

        $this->assertTrue($result);
        Http::assertSent(function ($request): bool {
            return str_contains($request->url(), 'sendMessage')
                && $request['chat_id'] === '99887766'
                && str_contains($request['text'], 'XZ12ABCD');
        });
    }
}
