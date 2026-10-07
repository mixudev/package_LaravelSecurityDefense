<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Evasion;

use PHPUnit\Framework\Attributes\DataProvider;
use Mixudev\SecurityDefense\Tests\Feature\Adversarial\Concerns\RegistersWafProbeRoute;
use Mixudev\SecurityDefense\Tests\TestCase;

class EncodedSqlInjectionTest extends TestCase
{
    use RegistersWafProbeRoute;

    protected function setUp(): void
    {
        parent::setUp();
        $this->registerWafProbeRoutes();
        $this->withoutAutoJail();
    }

    #[DataProvider('payloadProvider')]
    public function test_encoded_sqli_is_blocked_in_query(string $payload): void
    {
        $this->assertSame(403, $this->probeGet($payload, '198.18.10.1')['status'], $payload);
    }

    #[DataProvider('payloadProvider')]
    public function test_encoded_sqli_is_blocked_in_form(string $payload): void
    {
        $this->assertSame(403, $this->probeForm('q', $payload, '198.18.10.2')['status'], $payload);
    }

    #[DataProvider('payloadProvider')]
    public function test_encoded_sqli_is_blocked_in_json(string $payload): void
    {
        $this->assertSame(403, $this->probeJson('q', $payload, '198.18.10.3')['status'], $payload);
    }

    public function test_benign_search_is_allowed(): void
    {
        $this->assertSame(200, $this->probeGet('select items from the shop', '198.18.10.4')['status']);
    }

    public static function payloadProvider(): array
    {
        return [
            'encoded union' => ['1%20UNION%20SELECT%201'],
            'double encoded union' => ['1%2520UNION%2520SELECT%25201'],
            'plus separated union' => ['1+UNION+SELECT+1'],
            'encoded quote tautology' => ['%27%20OR%201%3D1--'],
            'unicode quote tautology' => ['\\u0027 OR 1=1--'],
            'mixed case union' => ['1%20uNiOn%20sElEcT%201'],
            'tab separated select' => ["1%09UNION%0ASELECT%091"],
            'encoded comment union' => ['1%2F%2A%2A%2FUNION%2F%2A%2A%2FSELECT%201'],
            'encoded sleep' => ['1%20AND%20SLEEP%282%29'],
            'encoded drop' => ['DROP%20TABLE%20users'],
            'encoded information schema' => ['%27%20UNION%20SELECT%20table_name%20FROM%20information_schema.tables--'],
            'encoded order by' => ['1%20ORDER%20BY%20100'],
            'encoded insert' => ['INSERT%20INTO%20users%20%28x%29%20VALUES%281%29'],
            'encoded delete' => ['DELETE%20FROM%20users%20WHERE%201%3D1'],
            'encoded case' => ['1%20AND%20CASE%20WHEN%201%3D1%20THEN%201%20ELSE%200%20END'],
            'literal escaped whitespace' => ["1\\sUNION\\sSELECT\\s1"],
            'crlf mixed case' => ["1'%0D%0AUnIoN%20SeLeCt%201"],
            'encoded hash comment' => ['%27%20%23'],
            'encoded waitfor' => ['%27%3B%20WAITFOR%20DELAY%20%270%3A0%3A5%27--'],
            'encoded char function' => ['CHAR%2839%29%20OR%201%3D1'],
        ];
    }
}
