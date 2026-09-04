<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Mixudev\SecurityDefense\DTO\SecurityEvent;
use PHPUnit\Framework\TestCase;

class SecurityEventTest extends TestCase
{
    public function test_it_instantiates_and_sanitizes_metadata(): void
    {
        $event = new SecurityEvent(
            ip: '192.168.1.50',
            identifier: 'user@example.com',
            eventType: 'LoginFailed',
            userAgent: 'Mozilla/5.0',
            metadata: [
                'password' => 'secretPass',
                'login_method' => 'web_form',
            ]
        );

        $this->assertEquals('192.168.1.50', $event->ip);
        $this->assertEquals('user@example.com', $event->identifier);
        $this->assertEquals('LoginFailed', $event->eventType);
        $this->assertEquals('[REDACTED]', $event->metadata['password']);
        $this->assertEquals('web_form', $event->metadata['login_method']);
    }

    public function test_from_array_factory(): void
    {
        $data = [
            'ip' => '10.0.0.1',
            'identifier' => 'admin',
            'eventType' => 'AccountLocked',
            'userAgent' => 'PostmanRuntime',
            'metadata' => [
                'reason' => 'Too many failed attempts',
                'token' => 'leaked_token',
            ],
        ];

        $event = SecurityEvent::fromArray($data);

        $this->assertEquals('10.0.0.1', $event->ip);
        $this->assertEquals('admin', $event->identifier);
        $this->assertEquals('AccountLocked', $event->eventType);
        $this->assertEquals('[REDACTED]', $event->metadata['token']);
        $this->assertEquals('Too many failed attempts', $event->metadata['reason']);
    }
}
