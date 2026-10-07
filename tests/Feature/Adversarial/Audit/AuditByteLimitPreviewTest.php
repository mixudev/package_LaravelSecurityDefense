<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Audit;

use PHPUnit\Framework\Attributes\DataProvider;
use Illuminate\Http\Request;
use Mixudev\SecurityDefense\Services\AuditPayloadSanitizer;
use Mixudev\SecurityDefense\Tests\TestCase;

class AuditByteLimitPreviewTest extends TestCase
{
    #[DataProvider('limitProvider')]
    public function test_oversized_snapshot_is_bounded_and_warns(int $limit, int $fields): void
    {
        config()->set('security-defense.data_audit.max_payload_snapshot_bytes', $limit);
        $body = [];
        for ($i = 0; $i < $fields; $i++) $body['field_'.$i] = str_repeat('x', 500);
        $request = Request::create('/audit', 'POST', $body);

        $snapshot = (new AuditPayloadSanitizer())->resolvePayloadSnapshot($request);

        $this->assertIsArray($snapshot);
        $this->assertArrayHasKey('_snapshot_warning', $snapshot);
        $this->assertArrayHasKey('preview', $snapshot);
        $this->assertLessThanOrEqual($limit, strlen((string) json_encode($snapshot)));
        $this->assertStringNotContainsString('<script', strtolower((string) json_encode($snapshot)));
    }

    #[DataProvider('limitProvider')]
    public function test_preview_truncates_long_values(int $limit, int $fields): void
    {
        config()->set('security-defense.data_audit.max_payload_snapshot_bytes', $limit);
        $request = Request::create('/audit', 'POST', ['first' => str_repeat('x', 1000)] + array_fill(0, $fields, 'safe'));
        $snapshot = (new AuditPayloadSanitizer())->resolvePayloadSnapshot($request);

        $this->assertLessThanOrEqual($limit, strlen((string) json_encode($snapshot)));
    }

    /** @return array<string,array{0:int,1:int}> */
    public static function limitProvider(): array
    {
        return [
            'tiny' => [128, 12], 'small' => [256, 12], 'normal' => [512, 16],
            'one kb' => [1024, 20], 'two kb' => [2048, 30], 'four kb' => [4096, 40],
            'eight kb' => [8192, 50], 'odd ceiling' => [777, 19],
        ];
    }
}
