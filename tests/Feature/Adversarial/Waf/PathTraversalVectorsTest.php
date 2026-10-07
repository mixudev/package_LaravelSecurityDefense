<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Waf;

use PHPUnit\Framework\Attributes\DataProvider;
use Mixudev\SecurityDefense\Tests\Feature\Adversarial\Concerns\RegistersWafProbeRoute;
use Mixudev\SecurityDefense\Tests\TestCase;

/**
 * Path traversal / LFI / RFI corpus through the REAL middleware.
 *
 * Attacker POV: unix, windows, url-encoded, double-encoded, unicode, and
 * null-byte-terminated traversal chains.
 */
class PathTraversalVectorsTest extends TestCase
{
    use RegistersWafProbeRoute;

    protected function setUp(): void
    {
        parent::setUp();
        $this->registerWafProbeRoutes();
        $this->withoutAutoJail();
    }

    #[DataProvider('payloadProvider')]
    public function test_query_traversal_is_blocked(string $payload): void
    {
        $result = $this->probeGet($payload, '198.18.3.1');
        $this->assertSame(403, $result['status'], "Query traversal not blocked: {$payload}");
    }

    #[DataProvider('payloadProvider')]
    public function test_form_traversal_is_blocked(string $payload): void
    {
        $result = $this->probeForm('file', $payload, '198.18.3.2');
        $this->assertSame(403, $result['status'], "Form traversal not blocked: {$payload}");
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function payloadProvider(): array
    {
        return [
            'unix simple' => ['../../../etc/passwd'],
            'unix deep' => ['../../../../../../../../etc/passwd'],
            'unix file' => ['../../etc/passwd'],
            'windows simple' => ['..\\..\\windows\\win.ini'],
            'windows system32' => ['..\\windows\\system32\\config\\sam'],
            'boot ini' => ['../../boot.ini'],
            'url encoded slash' => ['..%2f..%2fetc%2fpasswd'],
            'url encoded backslash' => ['..%5c..%5cwindows%5cwin.ini'],
            'double encoded' => ['..%252f..%252fetc%252fpasswd'],
            'null byte' => ["../../etc/passwd%00"],
            'null byte raw' => ["../../etc/passwd\x00.jpg"],
            'dot dot slash etc passwd' => ['....//....//etc/passwd'],
            'mixed separators' => ['..\\/../etc/passwd'],
            'dot dot slash only' => ['../../'],
            'proc self' => ['../../../proc/self/environ'],
            'windows hosts' => ['..\\..\\windows\\system32\\drivers\\etc\\hosts'],
            'shadow file' => ['../../etc/shadow'],
            'ssh key' => ['../../root/.ssh/id_rsa'],
            'env file' => ['../../.env'],
            'env file dotslash' => ['../../../.env'],
            'git config' => ['../../.git/config'],
            'composer json' => ['../../composer.json'],
            'backup dump' => ['../../backup.sql'],
            'log file' => ['../../var/log/auth.log'],
            'tmp file' => ['../../tmp/session.txt'],
            'php session' => ['../../var/lib/php/sessions/sess_abc123'],
            'win.ini full' => ['..%2f..%2fwindows%2fwin.ini'],
            'traversal with extension' => ['../../../etc/passwd%00.php'],
            'overlong unicode slash' => ["..\\u2215..\\u2215etc\\u2215passwd"],
        ];
    }

    public function test_benign_relative_paths_are_not_blocked(): void
    {
        foreach (['images/logo.png', 'docs/readme.md', 'assets/css/app.css'] as $path) {
            $result = $this->probeGet($path, '198.18.3.3');
            $this->assertSame(200, $result['status'], "False positive on benign path: {$path}");
        }
    }

    public function test_benign_version_strings_are_not_blocked(): void
    {
        $result = $this->probeGet('release/2.4.1', '198.18.3.4');
        $this->assertSame(200, $result['status']);
    }
}
