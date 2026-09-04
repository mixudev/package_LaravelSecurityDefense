<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Illuminate\Support\Facades\Mail;
use Mixudev\SecurityDefense\Channels\MailChannel;
use Mixudev\SecurityDefense\Mail\SecurityAlertMail;
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Tests\TestCase;

class MailChannelTest extends TestCase
{
    public function test_mail_channel_identifier_and_status(): void
    {
        $channel = new MailChannel();
        $this->assertSame('mail', $channel->identifier());

        config()->set('security-defense.alerts.mail.enabled', false);
        $this->assertFalse($channel->isEnabled());

        config()->set('security-defense.alerts.mail.enabled', true);
        $this->assertTrue($channel->isEnabled());
    }

    public function test_mail_channel_is_configured_with_valid_recipients(): void
    {
        $channel = new MailChannel();

        config()->set('security-defense.alerts.mail.to', null);
        $this->assertFalse($channel->isConfigured());

        config()->set('security-defense.alerts.mail.to', 'security-ops@company.com');
        $this->assertTrue($channel->isConfigured());
        $this->assertSame(['security-ops@company.com'], $channel->getRecipients());

        // Comma-separated list
        config()->set('security-defense.alerts.mail.to', 'sec1@test.com, sec2@test.com');
        $this->assertSame(['sec1@test.com', 'sec2@test.com'], $channel->getRecipients());

        // Array list
        config()->set('security-defense.alerts.mail.to', ['sec1@test.com', 'sec2@test.com']);
        $this->assertSame(['sec1@test.com', 'sec2@test.com'], $channel->getRecipients());
    }

    public function test_mail_channel_sends_security_alert_mail(): void
    {
        Mail::fake();

        config()->set('security-defense.alerts.mail.enabled', true);
        config()->set('security-defense.alerts.mail.to', 'soc@company.org');

        $channel = new MailChannel();

        $alert = new SecurityAlert([
            'severity' => 'critical',
            'threat_type' => 'credential_stuffing',
            'fingerprint' => 'fp-mail-test-123',
            'status' => 'new',
            'rule_identifier' => 'credential_stuffing',
            'metadata' => ['attacker_ip' => '198.51.100.42'],
        ]);
        $alert->save();

        $result = $channel->send($alert);

        $this->assertTrue($result);
        Mail::assertSent(SecurityAlertMail::class, function (SecurityAlertMail $mail) use ($alert) {
            return $mail->hasTo('soc@company.org') &&
                $mail->alert->id === $alert->id;
        });
    }
}
