<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Audit;

use PHPUnit\Framework\Attributes\DataProvider;
use Mixudev\SecurityDefense\Services\AuditPayloadSanitizer;
use Mixudev\SecurityDefense\Support\Sanitizer;
use Mixudev\SecurityDefense\Tests\TestCase;

class SecretRedactionCompletenessTest extends TestCase
{
    #[DataProvider('secretProvider')]
    public function test_canonical_secret_keys_are_redacted(string $key): void
    {
        $clean = Sanitizer::clean([$key => 'DO_NOT_PERSIST_THIS_SECRET']);
        $this->assertSame('[REDACTED]', $clean[$key]);
    }

    #[DataProvider('secretProvider')]
    public function test_audit_masking_redacts_secret_keys(string $key): void
    {
        $masked = (new AuditPayloadSanitizer())->maskValues([$key => 'DO_NOT_PERSIST_THIS_SECRET'], [$key]);
        $this->assertStringNotContainsString('DO_NOT_PERSIST', json_encode($masked));
        $this->assertStringContainsString('REDACTED', $masked[$key]);
    }

    /** @return array<string,array{0:string}> */
    public static function secretProvider(): array
    {
        $keys = array_unique(array_merge(Sanitizer::sensitiveKeys(), [
            'PASSWORD', 'Authorization-Header', 'nested_access_token', 'my_private_key',
        ]));
        $out = [];
        foreach ($keys as $key) $out[strtolower($key)] = [$key];
        return $out;
    }
}
