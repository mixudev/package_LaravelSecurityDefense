<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Evasion;

use PHPUnit\Framework\Attributes\DataProvider;
use Mixudev\SecurityDefense\Tests\Feature\Adversarial\Concerns\RegistersWafProbeRoute;
use Mixudev\SecurityDefense\Tests\TestCase;

class EncodedXssTest extends TestCase
{
    use RegistersWafProbeRoute;

    protected function setUp(): void { parent::setUp(); $this->registerWafProbeRoutes(); $this->withoutAutoJail(); }

    #[DataProvider('payloadProvider')]
    public function test_obfuscated_xss_is_blocked_in_form(string $payload): void { $this->assertSame(403, $this->probeForm('html', $payload, '198.18.11.1')['status'], $payload); }

    #[DataProvider('payloadProvider')]
    public function test_obfuscated_xss_is_blocked_in_json(string $payload): void { $this->assertSame(403, $this->probeJson('html', $payload, '198.18.11.2')['status'], $payload); }

    #[DataProvider('payloadProvider')]
    public function test_obfuscated_xss_is_blocked_in_query(string $payload): void { $this->assertSame(403, $this->probeGet($payload, '198.18.11.3')['status'], $payload); }

    public function test_benign_markup_is_allowed(): void { $this->assertSame(200, $this->probeForm('html', '<p>Hello, world</p>', '198.18.11.4')['status']); }

    public static function payloadProvider(): array
    {
        return [
            'encoded script' => ['%3Cscript%3Ealert%281%29%3C%2Fscript%3E'],
            'double encoded script' => ['%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E'],
            'mixed case script' => ['<ScRiPt>alert(1)</sCrIpT>'],
            'encoded javascript' => ['java%73cript%3Aalert%281%29'],
            'encoded svg handler' => ['%3Csvg%20onload%3Dalert%281%29%3E'],
            'encoded image handler' => ['%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E'],
            'encoded iframe' => ['%3Ciframe%20src%3Djavascript%3Aalert%281%29%3E'],
            'encoded data html' => ['data%3Atext%2Fhtml%2C%3Cscript%3Ealert%281%29'],
            'unicode script' => ['\\u003Cscript\\u003Ealert(1)\\u003C\\u002Fscript\\u003E'],
            'document cookie' => ['document%2Ecookie'],
            'window location' => ['window%2Elocation%3D%22%2F%2Fevil%22'],
            'prompt call' => ['prompt%281%29'],
            'confirm call' => ['confirm%281%29'],
            'encoded onmouseover' => ['%3Cdiv%20onmouseover%3Dalert%281%29%3Ex%3C%2Fdiv%3E'],
            'encoded math tag' => ['%3Cmath%3E%3Cmaction%20actiontype%3Dstatusline%3E'],
            'xlink handler' => ['xlink%3Ahref%3D%22javascript%3Aalert%281%29%22'],
            'split script close' => ['%3Cscript%3Efoo%3C%2Fscript%3E'],
            'encoded vbscript' => ['vbscript%3Amsgbox%281%29'],
            'encoded onclick' => ['onclick%3Dalert%281%29'],
            'encoded onfocus' => ['onfocus%3Dalert%281%29'],
        ];
    }
}
