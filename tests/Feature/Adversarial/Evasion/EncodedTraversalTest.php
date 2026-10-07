<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Evasion;

use PHPUnit\Framework\Attributes\DataProvider;
use Mixudev\SecurityDefense\Tests\Feature\Adversarial\Concerns\RegistersWafProbeRoute;
use Mixudev\SecurityDefense\Tests\TestCase;

class EncodedTraversalTest extends TestCase
{
    use RegistersWafProbeRoute;
    protected function setUp(): void { parent::setUp(); $this->registerWafProbeRoutes(); $this->withoutAutoJail(); }
    #[DataProvider('payloadProvider')]
    public function test_encoded_traversal_is_blocked_in_query(string $payload): void { $this->assertSame(403, $this->probeGet($payload, '198.18.12.1')['status'], $payload); }
    #[DataProvider('payloadProvider')]
    public function test_encoded_traversal_is_blocked_in_form(string $payload): void { $this->assertSame(403, $this->probeForm('path', $payload, '198.18.12.2')['status'], $payload); }
    #[DataProvider('payloadProvider')]
    public function test_encoded_traversal_is_blocked_in_json(string $payload): void { $this->assertSame(403, $this->probeJson('path', $payload, '198.18.12.3')['status'], $payload); }
    public function test_benign_path_is_allowed(): void { $this->assertSame(200, $this->probeGet('/products/2026/report', '198.18.12.4')['status']); }
    public static function payloadProvider(): array { return [
        'unix parent' => ['../etc/passwd'], 'encoded slash' => ['..%2Fetc%2Fpasswd'], 'double encoded slash' => ['..%252Fetc%252Fpasswd'],
        'encoded backslash' => ['..%5Cwindows%5Cwin.ini'], 'double encoded backslash' => ['..%255Cwindows%255Cwin.ini'],
        'mixed separators' => ['..%2f..%5cetc%2fpasswd'], 'windows drive' => ['C%3A%5Cwindows%5Cwin.ini'],
        'unix passwd' => ['etc%2Fpasswd'], 'windows ini' => ['windows%5Cwin.ini'], 'boot ini' => ['..%2Fboot.ini'],
        'null suffix' => ['..%2Fetc%2Fpasswd%00.jpg'], 'encoded dot' => ['%2E%2E%2Fetc%2Fpasswd'],
        'double encoded dot' => ['%252E%252E%252Fetc%252Fpasswd'], 'mixed case windows' => ['..%5cWindows%5cWIN.INI'],
        'many parents' => ['..%2F..%2F..%2Fetc%2Fpasswd'], 'slash escaped' => ['..\\etc\\passwd'],
        'encoded null' => ['%00..%2Fetc%2Fpasswd'], 'path in filename' => ['avatar..%2Fetc%2Fpasswd.png'],
    ]; }
}
