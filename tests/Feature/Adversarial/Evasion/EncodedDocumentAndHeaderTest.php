<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Evasion;

use PHPUnit\Framework\Attributes\DataProvider;
use Mixudev\SecurityDefense\Tests\Feature\Adversarial\Concerns\RegistersWafProbeRoute;
use Mixudev\SecurityDefense\Tests\TestCase;

class EncodedDocumentAndHeaderTest extends TestCase
{
    use RegistersWafProbeRoute;
    protected function setUp(): void { parent::setUp(); $this->registerWafProbeRoutes(); $this->withoutAutoJail(); }
    #[DataProvider('payloadProvider')]
    public function test_encoded_document_or_header_attack_is_blocked_in_form(string $payload): void { $this->assertSame(403, $this->probeForm('document', $payload, '198.18.16.1')['status'], $payload); }
    #[DataProvider('payloadProvider')]
    public function test_encoded_document_or_header_attack_is_blocked_in_json(string $payload): void { $this->assertSame(403, $this->probeJson('document', $payload, '198.18.16.2')['status'], $payload); }
    #[DataProvider('payloadProvider')]
    public function test_encoded_document_or_header_attack_is_blocked_in_query(string $payload): void { $this->assertSame(403, $this->probeGet($payload, '198.18.16.3')['status'], $payload); }
    public function test_benign_document_is_allowed(): void { $this->assertSame(200, $this->probeForm('document', 'ordinary text with a line break', '198.18.16.4')['status']); }
    public static function payloadProvider(): array { return [
        'doctype' => ['%3C%21DOCTYPE%20foo%20SYSTEM%20%22file%3A%2F%2F%2Fetc%2Fpasswd%22%3E'], 'entity system' => ['%3C%21ENTITY%20x%20SYSTEM%20%22file%3A%2F%2F%2Fetc%2Fpasswd%22%3E'],
        'entity public' => ['%3C%21ENTITY%20x%20PUBLIC%20%22id%22%20%22url%22%3E'], 'schema location' => ['xsi%3AnoNamespaceSchemaLocation%3D%22http%3A%2F%2Fevil.test%22'],
        'xmlns xsi' => ['xmlns%3Axsi%3D%22http%3A%2F%2Fwww.w3.org%2F2001%2FXMLSchema-instance%22'], 'double doctype' => ['%253C%2521DOCTYPE%2520foo%2520SYSTEM%2520%2522file%253A%252F%252F%252Fetc%252Fpasswd%2522%253E'],
        'crlf cookie' => ["hello%0D%0ASet-Cookie%3A%20session%3Devil"], 'crlf location' => ["hello%0A Location%3A%20https%3A%2F%2Fevil.test"],
        'crlf x header' => ["hello%0D%0AX-Injected%3A%20yes"], 'bare newline header' => ["hello%0AContent-Type%3A%20text%2Fhtml"],
        'encoded set cookie' => ['x%0D%0ASet-Cookie%3A%20admin%3D1'], 'encoded location' => ['x%0D%0ALocation%3A%20%2Fadmin'],
        'unicode doctype' => ['\\u003C!DOCTYPE foo SYSTEM \\u0022file:///etc/passwd\\u0022\\u003E'], 'unicode entity' => ['\\u003C!ENTITY x SYSTEM \\u0022file:///etc/passwd\\u0022\\u003E'],
        'mixed xxe' => ['%3C%21DoCtYpE%20foo%20SyStEm%20%22file%3A%2F%2F%2Fetc%2Fpasswd%22%3E'], 'encoded xsi' => ['%78%73%69%3AnoNamespaceSchemaLocation%3D%22x%22'],
        'double crlf' => ['x%250D%250ASet-Cookie%3A%20evil%3D1'], 'folded header' => ["x%0D%0A%09X-Forwarded-Host%3A%20evil.test"],
        'entity external' => ['%3C%21ENTITY%20xx%20SYSTEM%20%22http%3A%2F%2F169.254.169.254%22%3E'],
    ]; }
}
