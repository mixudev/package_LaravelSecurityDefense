<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Waf;

use PHPUnit\Framework\Attributes\DataProvider;
use Mixudev\SecurityDefense\Tests\Feature\Adversarial\Concerns\RegistersWafProbeRoute;
use Mixudev\SecurityDefense\Tests\TestCase;

/**
 * Cross-site scripting corpus through the REAL middleware.
 *
 * Attacker POV: reflected, stored, obfuscated, and DOM-based shapes, plus the
 * encodings Burp/OWASP ZAP emit after their transformation passes.
 */
class XssVectorsTest extends TestCase
{
    use RegistersWafProbeRoute;

    protected function setUp(): void
    {
        parent::setUp();
        $this->registerWafProbeRoutes();
        $this->withoutAutoJail();
    }

    #[DataProvider('payloadProvider')]
    public function test_query_string_xss_is_blocked(string $payload): void
    {
        $result = $this->probeGet($payload, '198.18.2.1');
        $this->assertSame(403, $result['status'], "Query XSS not blocked: {$payload}");
    }

    #[DataProvider('payloadProvider')]
    public function test_json_body_xss_is_blocked(string $payload): void
    {
        $result = $this->probeJson('comment', $payload, '198.18.2.2');
        $this->assertSame(403, $result['status'], "JSON XSS not blocked: {$payload}");
    }

    #[DataProvider('payloadProvider')]
    public function test_form_body_xss_is_blocked(string $payload): void
    {
        $result = $this->probeForm('comment', $payload, '198.18.2.3');
        $this->assertSame(403, $result['status'], "Form XSS not blocked: {$payload}");
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function payloadProvider(): array
    {
        return [
            'script tag' => ['<script>alert(1)</script>'],
            'script cookie' => ['<script>alert(document.cookie)</script>'],
            'script no close' => ['<script>alert(1)'],
            'closing script' => ['</script>'],
            'uppercase script' => ['<SCRIPT>alert(1)</SCRIPT>'],
            'mixed case script' => ['<ScRiPt>alert(1)</sCrIpT>'],
            'img onerror' => ['<img src=x onerror=alert(1)>'],
            'svg onload' => ['<svg onload=alert(1)>'],
            'body onload' => ['<body onload=alert(1)>'],
            'iframe javascript' => ['<iframe src="javascript:alert(1)"></iframe>'],
            'input onfocus' => ['<input onfocus=alert(1) autofocus>'],
            'details ontoggle' => ['<details open ontoggle=alert(1)>'],
            'marquee onstart' => ['<marquee onstart=alert(1)>'],
            'javascript uri' => ['javascript:alert(document.cookie)'],
            'data uri html' => ['data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='],
            'vbscript uri' => ['vbscript:msgbox(1)'],
            'event onerror' => ['" onerror="alert(1)'],
            'event onload' => ['" onload="alert(1)'],
            'event onclick' => ['" onclick="alert(1)'],
            'event onmouseover' => ['" onmouseover="alert(1)'],
            'event onfocus' => ['" onfocus="alert(1)'],
            'event onsubmit' => ['" onsubmit="alert(1)'],
            'document location' => ['document.location="http://evil.example"'],
            'window location' => ['window.location.href="http://evil.example"'],
            'alert call' => ['alert(String.fromCharCode(88,83,83))'],
            'prompt call' => ['prompt(1)'],
            'confirm call' => ['confirm(1)'],
            'template literal xss' => ['${alert(1)}'],
            'comment breakout' => ['<!--><script>alert(1)</script>'],
            'svg animate' => ['<svg><animate onbegin=alert(1) attributeName=x dur=1s>'],
            'math xlink' => ['<math><maction actiontype="statusline#http://evil.example">'],
            'object data' => ['<object data="javascript:alert(1)">'],
            'embed src' => ['<embed src="javascript:alert(1)">'],
            'form action' => ['<form action="javascript:alert(1)"><input type=submit>'],
            'isindex formaction' => ['<isindex type=image src=1 onerror=alert(1)>'],
            'base tag' => ['<base href="javascript:">'],
            'meta refresh' => ['<meta http-equiv="refresh" content="0;url=javascript:alert(1)">'],
            'style expression' => ['<style>body{background:url("javascript:alert(1)")}</style>'],
            'quoted script attr' => ['"><script>alert(1)</script>'],
            'single quote script' => ["'><script>alert(1)</script>"],
            'backtick script' => ['`<script>alert(1)</script>`'],
        ];
    }

    public function test_benign_html_in_a_search_box_is_not_blocked(): void
    {
        foreach (['how to write a script tag', 'the alert on my phone went off', 'buy a prompt engineering book'] as $text) {
            $result = $this->probeGet($text, '198.18.2.4');
            $this->assertSame(200, $result['status'], "False positive: {$text}");
        }
    }

    public function test_benign_code_snippet_text_is_not_blocked(): void
    {
        $result = $this->probeGet('CSP nonce example', '198.18.2.5');
        $this->assertSame(200, $result['status']);
    }
}
