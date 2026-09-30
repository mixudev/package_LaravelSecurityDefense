<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Services;

use Illuminate\Support\Facades\Mail;
use Mixudev\SecurityDefense\Mail\DashboardOtpMail;

/** Deliver a dashboard OTP through exactly one configured channel. */
final class DashboardOtpDispatcher
{
    public function canSend(): bool
    {
        return $this->resolveChannel() !== null;
    }

    /**
     * Send the code without logging or returning it.
     * Transport failures return false so the controller can fail closed.
     */
    public function send(string $code): bool
    {
        return match ($this->resolveChannel()) {
            'email' => $this->sendEmail($code),
            'telegram' => $this->sendTelegram($code),
            default => false,
        };
    }

    private function resolveChannel(): ?string
    {
        $channel = (string) config('security-defense.dashboard.otp.channel', '');

        if ($channel === 'email') {
            $email = (string) config('security-defense.dashboard.otp.email', '');

            return filter_var($email, FILTER_VALIDATE_EMAIL) !== false ? 'email' : null;
        }

        if ($channel === 'telegram') {
            $enabled = (bool) config('security-defense.alerts.telegram.enabled', false);
            $chatId = (string) config('security-defense.alerts.telegram.chat_id', '');
            $token = (string) config('security-defense.alerts.telegram.bot_token', '');

            return $enabled && $chatId !== '' && $token !== '' ? 'telegram' : null;
        }

        return null;
    }

    private function sendEmail(string $code): bool
    {
        try {
            Mail::to((string) config('security-defense.dashboard.otp.email'))
                ->send(new DashboardOtpMail($code));

            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    private function sendTelegram(string $code): bool
    {
        $chatId = (string) config('security-defense.alerts.telegram.chat_id', '');
        $ttlMinutes = (int) ceil(
            max(60, (int) config('security-defense.dashboard.otp.ttl_seconds', 300)) / 60
        );
        $message = "[Security Defense] Dashboard authorization code\n\n"
            . "Code: {$code}\n\n"
            . "Valid for {$ttlMinutes} minute(s). Do not share this code.";

        return app(TelegramApiClient::class)->sendMessage($chatId, $message);
    }
}
