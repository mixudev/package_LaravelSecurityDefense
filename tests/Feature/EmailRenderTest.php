<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Support\Facades\Mail;
use Mixudev\SecurityDefense\Mail\SecurityAlertMail;
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Tests\TestCase;

class EmailRenderTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('app.key', 'base64:7VzK9gG2e+x8UfXoN9uC7x/2j6yD8Hw0Z1A2B3C4D5E=');
    }

    public function test_email_uses_modular_layout_and_components(): void
    {
        $alert = SecurityAlert::query()->create([
            'severity' => 'critical',
            'threat_type' => 'credential_stuffing',
            'fingerprint' => 'fp-email-render-999',
            'status' => 'new',
            'rule_identifier' => 'credential_stuffing',
            'metadata' => ['attacker_ip' => '198.51.100.42'],
        ]);

        $html = (new SecurityAlertMail($alert))
            ->render();

        // Uses layout
        $this->assertStringContainsString('SECURITY DEFENSE SIEM', $html);
        // Light professional theme (no dark navy bg)
        $this->assertStringNotContainsString('#0b0f19', $html);
        $this->assertStringNotContainsString('#111827', $html);
        // Severity badge renders
        $this->assertStringContainsString('CRITICAL', $html);
        // Detail row renders with sanitized metadata
        $this->assertStringContainsString('Sanitized Telemetry', $html);
        $this->assertStringContainsString('198.51.100.42', $html);
        // Footer present
        $this->assertStringContainsString('All credentials, passwords, and authorization tokens have been sanitized', $html);
    }
}
