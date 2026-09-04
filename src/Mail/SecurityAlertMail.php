<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Queue\SerializesModels;
use Mixudev\SecurityDefense\Models\SecurityAlert;

/**
 * Enterprise HTML security alert notification mailable.
 */
class SecurityAlertMail extends Mailable
{
    use Queueable, SerializesModels;

    public function __construct(
        public readonly SecurityAlert $alert
    ) {}

    /**
     * Build the message.
     */
    public function build(): self
    {
        $prefix = (string) config('security-defense.alerts.mail.subject_prefix', '[SECURITY DEFENSE ALERT]');
        $severity = strtoupper($this->alert->severity);
        $threatType = ucwords(str_replace('_', ' ', $this->alert->threat_type));
        $subject = "{$prefix} [{$severity}] {$threatType} Detected";

        return $this->subject($subject)
            ->view('security-defense::emails.alert', [
                'alert' => $this->alert,
                'metadata' => $this->alert->metadata ?? [],
                'appName' => config('app.name', 'Laravel Application'),
                'appEnv' => app()->environment(),
            ]);
    }
}
