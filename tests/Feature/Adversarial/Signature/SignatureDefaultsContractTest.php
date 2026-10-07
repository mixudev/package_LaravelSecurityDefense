<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Signature;

use Mixudev\SecurityDefense\Tests\TestCase;

/**
 * Configuration contract for signature rules whose lexical matches are noisy.
 * A host must explicitly opt into SSRF/XXE/CRLF after reviewing its traffic;
 * this guard prevents a future config edit from silently changing that posture.
 */
class SignatureDefaultsContractTest extends TestCase
{
    use ConfiguresSignatureRules;

    protected function setUp(): void
    {
        parent::setUp();
        // Reload package defaults (see ConfiguresSignatureRules): the testbench
        // fixture's published copy would otherwise decide "runtime default".
        $this->setUpSignatureProbe();
    }

    public function test_signature_defaults_are_fail_closed_in_package_file(): void
    {
        $config = require dirname(__DIR__, 4) . '/config/security-defense.php';
        $patterns = $config['detection']['rules']['payload_injection']['patterns'];

        $this->assertFalse($patterns['ssrf']);
        $this->assertFalse($patterns['xxe']);
        $this->assertFalse($patterns['crlf_injection']);
    }

    public function test_signature_defaults_are_fail_closed_at_runtime(): void
    {
        $this->assertFalse((bool) config('security-defense.detection.rules.payload_injection.patterns.ssrf'));
        $this->assertFalse((bool) config('security-defense.detection.rules.payload_injection.patterns.xxe'));
        $this->assertFalse((bool) config('security-defense.detection.rules.payload_injection.patterns.crlf_injection'));
    }

    public function test_opt_in_categories_have_real_signatures(): void
    {
        $rule = app(\Mixudev\SecurityDefense\Rules\PayloadInjectionRule::class);
        foreach (['ssrf', 'xxe', 'crlf_injection', 'template_injection'] as $category) {
            config()->set("security-defense.detection.rules.payload_injection.patterns.{$category}", true);
            $this->assertTrue(
                $rule->inspect($this->probeFor($category))['matched'],
                "Configured signature has no executable match: {$category}"
            );
        }
    }

    public function test_opt_in_signature_names_are_stable(): void
    {
        $config = require dirname(__DIR__, 4) . '/config/security-defense.php';
        $patterns = $config['detection']['rules']['payload_injection']['patterns'];

        foreach (['ssrf', 'ssrf_localhost', 'xxe', 'crlf_injection', 'template_injection'] as $name) {
            $this->assertArrayHasKey($name, $patterns);
        }
    }

    public function test_unrelated_benign_text_is_not_a_signature_match(): void
    {
        $rule = app(\Mixudev\SecurityDefense\Rules\PayloadInjectionRule::class);
        config()->set('security-defense.detection.rules.payload_injection.patterns', [
            'ssrf' => true,
            'ssrf_localhost' => true,
            'xxe' => true,
            'crlf_injection' => true,
            'template_injection' => true,
        ]);

        foreach ([
            'https://example.test/docs',
            '<root><item>hello</item></root>',
            "first line\nsecond line",
            '{{ customer_name }}',
            'internal network policy documentation',
        ] as $value) {
            $this->assertFalse($rule->inspect($value)['matched'], "Benign signature corpus matched: {$value}");
        }
    }

    private function probeFor(string $category): string
    {
        return match ($category) {
            'ssrf' => 'http://169.254.169.254/latest/meta-data/',
            'xxe' => '<!DOCTYPE data SYSTEM "http://evil.test/a.dtd">',
            'crlf_injection' => "ok\r\nSet-Cookie: injected=true",
            'template_injection' => '{{ system("id") }}',
            default => throw new \InvalidArgumentException($category),
        };
    }
}
