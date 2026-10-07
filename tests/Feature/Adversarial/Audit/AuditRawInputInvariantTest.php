<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Audit;

use PHPUnit\Framework\Attributes\DataProvider;
use Mixudev\SecurityDefense\Middleware\RequestThreatScanner;
use Mixudev\SecurityDefense\Tests\TestCase;
use ReflectionClass;

class AuditRawInputInvariantTest extends TestCase
{
    public function test_scanner_source_keeps_raw_content_as_a_distinct_target(): void
    {
        $source = (string) file_get_contents((new ReflectionClass(RequestThreatScanner::class))->getFileName());
        $this->assertStringContainsString("'raw_content' => \$request->getContent()", $source);
        $this->assertStringContainsString("'body' => \$request->all()", $source);
        $this->assertStringContainsString('addDecodedTargets($inputsToScan)', $source);
    }

    #[DataProvider('rawInvariantProvider')]
    public function test_scanner_source_does_not_replace_raw_targets_with_sanitizer(string $forbidden): void
    {
        $source = (string) file_get_contents((new ReflectionClass(RequestThreatScanner::class))->getFileName());
        $this->assertStringNotContainsString($forbidden, $source);
    }

    /** @return array<string,array{0:string}> */
    public static function rawInvariantProvider(): array
    {
        return [
            'sanitizer target replacement' => ['$inputsToScan = Sanitizer::clean'],
            'clean string target replacement' => ['$inputsToScan = Sanitizer::cleanString'],
            'body overwritten by clean' => ['$inputsToScan[\'body\'] = Sanitizer'],
            'raw overwritten by clean' => ['$inputsToScan[\'raw_content\'] = Sanitizer'],
            'scanner receives sanitizer only' => ['$this->payloadRule->inspect(Sanitizer'],
            'target list overwritten' => ['$inputsToScan = [$this->sanitizer'],
            'raw list overwritten' => ['$inputsToScan = [\'raw_content\' => Sanitizer'],
            'sanitized raw alias' => ['\'raw_content\' => Sanitizer::cleanString'],
            'pre-scan normalization replacement' => ['$request->replace(Sanitizer'],
            'request overwrite' => ['$request->merge(Sanitizer'],
        ];
    }
}
