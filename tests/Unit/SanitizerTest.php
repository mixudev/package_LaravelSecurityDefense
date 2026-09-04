<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Mixudev\SecurityDefense\Support\Sanitizer;
use PHPUnit\Framework\TestCase;

class SanitizerTest extends TestCase
{
    public function test_it_redacts_sensitive_keys_recursively(): void
    {
        $input = [
            'username' => 'alice',
            'password' => 'SuperSecret123!',
            'password_confirmation' => 'SuperSecret123!',
            'access_token' => 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
            'api_key' => 'sk_live_1234567890',
            'nested' => [
                'bot_token' => '123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11',
                'credit_card' => '4111222233334444',
                'cvv' => '123',
                'safe_info' => 'harmless',
            ],
            'deep' => [
                'layer' => [
                    'authorization' => 'Bearer sensitive-token-string',
                    'auth_token' => 'xyz-token',
                ],
            ],
        ];

        $cleaned = Sanitizer::clean($input);

        $this->assertEquals('alice', $cleaned['username']);
        $this->assertEquals('[REDACTED]', $cleaned['password']);
        $this->assertEquals('[REDACTED]', $cleaned['password_confirmation']);
        $this->assertEquals('[REDACTED]', $cleaned['access_token']);
        $this->assertEquals('[REDACTED]', $cleaned['api_key']);

        $this->assertEquals('[REDACTED]', $cleaned['nested']['bot_token']);
        $this->assertEquals('[REDACTED]', $cleaned['nested']['credit_card']);
        $this->assertEquals('[REDACTED]', $cleaned['nested']['cvv']);
        $this->assertEquals('harmless', $cleaned['nested']['safe_info']);

        $this->assertEquals('[REDACTED]', $cleaned['deep']['layer']['authorization']);
        $this->assertEquals('[REDACTED]', $cleaned['deep']['layer']['auth_token']);
    }

    public function test_it_scrubs_bearer_tokens_inside_strings(): void
    {
        $text = 'Failed login header: Bearer abc123secrettokenfromclient==';
        $cleaned = Sanitizer::cleanString($text);

        $this->assertStringNotContainsString('abc123secrettokenfromclient==', $cleaned);
        $this->assertStringContainsString('Bearer [REDACTED]', $cleaned);
    }
}
