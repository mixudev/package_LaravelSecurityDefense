<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Mail\Mailable;
use Illuminate\Queue\SerializesModels;

/**
 * One-time dashboard authorization code email.
 *
 * The $code property is intentionally public so Mail::assertSent closures
 * can inspect it in tests, but it is marked readonly so nothing can modify it.
 * It should NEVER appear in any log statement.
 *
 * Implements ShouldBeEncrypted so a queued copy of this mailable is encrypted
 * at rest in the queue payload (database/Redis) instead of storing the OTP
 * code in plaintext rows readable by anyone with queue-table access.
 */
final class DashboardOtpMail extends Mailable implements ShouldBeEncrypted
{
    use Queueable, SerializesModels;

    public function __construct(public readonly string $code)
    {
    }

    public function build(): self
    {
        $ttlMinutes = (int) ceil(
            max(60, (int) config('security-defense.dashboard.otp.ttl_seconds', 300)) / 60
        );

        return $this
            ->subject('[Security Defense] Dashboard Authorization Code')
            ->view('security-defense::mail.otp', [
                'code' => $this->code,
                'ttlMinutes' => $ttlMinutes,
            ]);
    }
}
