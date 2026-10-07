<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Evasion;

use PHPUnit\Framework\Attributes\DataProvider;
use Mixudev\SecurityDefense\Tests\Feature\Adversarial\Concerns\RegistersWafProbeRoute;
use Mixudev\SecurityDefense\Tests\TestCase;

class EncodedNetworkPayloadTest extends TestCase
{
    use RegistersWafProbeRoute;
    protected function setUp(): void { parent::setUp(); $this->registerWafProbeRoutes(); $this->withoutAutoJail(); }
    #[DataProvider('payloadProvider')]
    public function test_encoded_network_payload_is_blocked_in_form(string $payload): void { $this->assertSame(403, $this->probeForm('url', $payload, '198.18.15.1')['status'], $payload); }
    #[DataProvider('payloadProvider')]
    public function test_encoded_network_payload_is_blocked_in_json(string $payload): void { $this->assertSame(403, $this->probeJson('url', $payload, '198.18.15.2')['status'], $payload); }
    #[DataProvider('payloadProvider')]
    public function test_encoded_network_payload_is_blocked_in_query(string $payload): void { $this->assertSame(403, $this->probeGet($payload, '198.18.15.3')['status'], $payload); }
    public function test_public_url_is_allowed(): void { $this->assertSame(200, $this->probeGet('https://example.test/docs', '198.18.15.4')['status']); }
    public static function payloadProvider(): array { return [
        'metadata ipv4' => ['http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data'], 'metadata bare' => ['169.254.169.254%2Flatest'],
        'private ten' => ['http%3A%2F%2F10.0.0.1%2Fadmin'], 'private 192' => ['http%3A%2F%2F192.168.1.1%2Fadmin'],
        'private 172' => ['http%3A%2F%2F172.16.0.1%2Fadmin'], 'gopher' => ['gopher%3A%2F%2F127.0.0.1%3A6379%2F_info'],
        'dict' => ['dict%3A%2F%2F127.0.0.1%3A11211%2Fstats'], 'file' => ['file%3A%2F%2F%2Fetc%2Fpasswd'],
        'ftp' => ['ftp%3A%2F%2F10.0.0.1%2Fsecret'], 'ldap' => ['ldap%3A%2F%2F192.168.1.1%2Fdc%3Dtest'],
        'tftp' => ['tftp%3A%2F%2F10.0.0.1%2Fboot'], 'scgi' => ['scgi%3A%2F%2F10.0.0.1%3A9000%2F'],
        'double metadata' => ['http%253A%252F%252F169.254.169.254%252Flatest'], 'zero host' => ['http%3A%2F%2F0.0.0.0%2Fadmin'],
        'metadata port' => ['https%3A%2F%2F169.254.169.254%3A80%2F'], 'encoded private' => ['%31%39%32.%31%36%38.1.1%2F'],
        'plus metadata' => ['http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%3Fx%3D1'], 'mixed private' => ['HTTP%3A%2F%2F10.1.2.3%2F'],
        'cloud token' => ['http%3A%2F%2F169.254.169.254%2Flatest%2Fapi%2Ftoken'], 'redis gopher' => ['gopher%3A%2F%2F10.0.0.2%3A6379%2F_%2A'],
    ]; }
}
