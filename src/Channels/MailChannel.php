<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Channels;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Mixudev\SecurityDefense\Contracts\AlertChannel;
use Mixudev\SecurityDefense\Mail\SecurityAlertMail;
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Throwable;

/**
 * Native Laravel Email alert delivery channel.
 * Uses application's configured mail transport (SMTP, SES, Resend, Mailgun, etc.).
 */
class MailChannel implements AlertChannel
{
    public function identifier(): string
    {
        return 'mail';
    }

    public function isEnabled(): bool
    {
        return (bool) config('security-defense.alerts.mail.enabled', false);
    }

    public function isConfigured(): bool
    {
        $recipients = $this->getRecipients();

        return !empty($recipients);
    }

    /**
     * Send security alert via Laravel native mailer.
     */
    public function send(SecurityAlert $alert): bool
    {
        if (!$this->isEnabled() || !$this->isConfigured()) {
            return false;
        }

        $recipients = $this->getRecipients();

        try {
            Mail::to($recipients)->send(new SecurityAlertMail($alert));

            return true;
        } catch (Throwable $e) {
            Log::warning('SecurityDefense: Exception occurred while delivering email alert.', [
                'alert_id' => $alert->id,
                'recipients' => $recipients,
                'error' => $e->getMessage(),
            ]);

            return false;
        }
    }

    /**
     * Resolve recipient email addresses from config.
     *
     * @return array<int, string>
     */
    public function getRecipients(): array
    {
        $to = config('security-defense.alerts.mail.to');

        if (empty($to)) {
            return [];
        }

        if (is_array($to)) {
            return array_filter(array_map('trim', $to));
        }

        if (is_string($to)) {
            return array_filter(array_map('trim', explode(',', $to)));
        }

        return [];
    }
}
