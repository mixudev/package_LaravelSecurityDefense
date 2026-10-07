<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Audit;

use PHPUnit\Framework\Attributes\DataProvider;
use Mixudev\SecurityDefense\Support\Sanitizer;
use Mixudev\SecurityDefense\Tests\TestCase;

/** Stored payloads must remain forensic-readable but never executable. */
class SanitizerStoredXssTest extends TestCase
{
    #[DataProvider('xssProvider')]
    public function test_stored_xss_is_defanged(string $payload, string $needle): void
    {
        $clean = Sanitizer::cleanString($payload);
        $this->assertStringNotContainsString('<script', strtolower($clean));
        $this->assertStringNotContainsString('<svg', strtolower($clean));
        $this->assertStringNotContainsString('javascript:', strtolower($clean));
        $this->assertStringContainsString($needle, $clean);
    }

    #[DataProvider('xssProvider')]
    public function test_nested_stored_xss_is_defanged(string $payload, string $needle): void
    {
        $clean = Sanitizer::clean(['outer' => ['inner' => $payload]]);
        $value = $clean['outer']['inner'];
        $this->assertStringNotContainsString('<', $value);
        $this->assertStringContainsString($needle, $value);
    }

    /** @return array<string,array{0:string,1:string}> */
    public static function xssProvider(): array
    {
        return [
            'script' => ['<script>alert(1)</script>', 'alert(1)'],
            'mixed script' => ['<ScRiPt src=x>payload</sCrIpT>', 'payload'],
            'svg event' => ['<svg onload=alert(1)>x</svg>', 'alert(1)'],
            'image event' => ['<img src=x onerror=alert(1)>x', 'alert(1)'],
            'iframe' => ['<iframe src="//evil.example">x</iframe>', 'evil.example'],
            'object' => ['<object data=x>payload</object>', 'payload'],
            'embed' => ['<embed src=x>', 'src=x'],
            'style' => ['<style>body{background:url(x)}</style>', 'background'],
            'meta' => ['<meta http-equiv=refresh content=0>', 'refresh'],
            'link' => ['<link rel=stylesheet href=x>', 'stylesheet'],
            'base' => ['<base href=//evil.example>', 'evil.example'],
            'onclick' => ['<div onclick=alert(1)>x</div>', 'alert(1)'],
            'onload' => ['<div onload=alert(2)>x</div>', 'alert(2)'],
            'onfocus' => ['<input onfocus=alert(3)>', 'alert(3)'],
            'javascript' => ['javascript:alert(4)', 'java_script:alert(4)'],
            'vbscript' => ['vbscript:alert(5)', 'vb_script:alert(5)'],
            'data html' => ['data:text/html,<script>x</script>', 'd_ata:text/html'],
            'closing arbitrary' => ['</textarea><script>x</script>', 'textarea'],
            'unicode text' => ['<script>\u0061lert(6)</script>', '\\u0061lert(6)'],
            'quoted event' => ['<img onerror="alert(7)">', 'alert(7)'],
        ];
    }
}
