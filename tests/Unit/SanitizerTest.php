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

    public function test_it_defangs_dangerous_payloads_without_breaking_readability(): void
    {
        $payloads = [
            'xss_script' => '<script>alert("pwned")</script>',
            'xss_event' => '<img src=x onerror=alert(1)>',
            'xss_proto' => 'javascript:document.location="http://evil.com"',
            'vbscript' => 'vbscript:msgbox("hello")',
            'svg_tag' => '<svg onload=alert(1)>',
            'iframe_tag' => '<iframe src="http://evil.com"></iframe>',
            'crlf_chars' => "Normal text\x00with null and \x07bell",
            'markdown_breakout' => "```json\nattacker breakout```",
        ];

        $cleaned = Sanitizer::clean($payloads);

        // Scripts neutralized
        $this->assertSame('[script]alert("pwned")[/script]', $cleaned['xss_script']);
        $this->assertSame('<img src=x onerror_neutralized=alert(1)>', $cleaned['xss_event']);
        $this->assertSame('java_script:document.location="http://evil.com"', $cleaned['xss_proto']);
        $this->assertSame('vb_script:msgbox("hello")', $cleaned['vbscript']);
        $this->assertSame('[svg onload_neutralized=alert(1)]', $cleaned['svg_tag']);
        $this->assertSame('[iframe src="http://evil.com"][/iframe]', $cleaned['iframe_tag']);

        // Control characters stripped
        $this->assertSame('Normal textwith null and bell', $cleaned['crlf_chars']);

        // Markdown backticks defanged
        $this->assertSame("'''json\nattacker breakout'''", $cleaned['markdown_breakout']);
    }
}

