<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Illuminate\Http\Request;
use Mixudev\SecurityDefense\Http\Middleware\EnsureLocalAccess;
use Mixudev\SecurityDefense\Tests\TestCase;
use ReflectionMethod;

final class EnsureLocalAccessLogRedactionTest extends TestCase
{
    private EnsureLocalAccess $middleware;
    private ReflectionMethod $safeLogPathMethod;

    protected function setUp(): void
    {
        parent::setUp();
        $this->middleware = new EnsureLocalAccess();
        $this->safeLogPathMethod = new ReflectionMethod(EnsureLocalAccess::class, 'safeLogPath');
    }

    private function safeLogPath(Request $request): string
    {
        return $this->safeLogPathMethod->invoke($this->middleware, $request);
    }

    public function test_redacts_64_hex_session_path_segment_from_log_path(): void
    {
        $sessionPath = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';
        $request = Request::create('/' . $sessionPath . '/live-events', 'GET');

        $result = $this->safeLogPath($request);

        self::assertStringNotContainsString($sessionPath, $result);
        self::assertStringContainsString('[redacted]', $result);
    }

    public function test_redacts_150_char_capability_token_from_log_path(): void
    {
        $token = str_repeat('a', 150);
        $request = Request::create('/' . $token, 'GET');

        $result = $this->safeLogPath($request);

        self::assertStringNotContainsString($token, $result);
        self::assertStringContainsString('[redacted]', $result);
    }

    public function test_preserves_regular_short_paths_without_redacting(): void
    {
        $request = Request::create('/login', 'GET');

        $result = $this->safeLogPath($request);

        self::assertSame('login', $result);
    }
}
