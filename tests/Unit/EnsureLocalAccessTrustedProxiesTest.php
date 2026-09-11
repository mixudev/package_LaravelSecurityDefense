<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Illuminate\Http\Request;
use Mixudev\SecurityDefense\Http\Middleware\EnsureLocalAccess;
use Mixudev\SecurityDefense\Tests\TestCase;
use ReflectionMethod;

final class EnsureLocalAccessTrustedProxiesTest extends TestCase
{
    private EnsureLocalAccess $middleware;
    private ReflectionMethod $resolveMethod;

    protected function setUp(): void
    {
        parent::setUp();
        $this->middleware = new EnsureLocalAccess();
        $this->resolveMethod = new ReflectionMethod(EnsureLocalAccess::class, 'resolveClientIp');
    }

    private function resolve(Request $request): string
    {
        return $this->resolveMethod->invoke($this->middleware, $request);
    }

    public function test_ignores_forwarded_headers_from_untrusted_peer(): void
    {
        config()->set('security-defense.dashboard.trusted_proxies', ['127.0.0.1', '::1']);

        $request = Request::create('/security-defense', 'GET', [], [], [], [
            'REMOTE_ADDR' => '203.0.113.88',
            'HTTP_X_FORWARDED_FOR' => '127.0.0.1',
        ]);

        // Peer 203.0.113.88 is NOT in trusted_proxies -> must ignore X-Forwarded-For
        self::assertSame('203.0.113.88', $this->resolve($request));
    }

    public function test_honors_forwarded_headers_from_trusted_loopback_proxy(): void
    {
        config()->set('security-defense.dashboard.trusted_proxies', ['127.0.0.1', '::1']);

        Request::setTrustedProxies(['127.0.0.1'], Request::HEADER_X_FORWARDED_FOR);

        $request = Request::create('/security-defense', 'GET', [], [], [], [
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_X_FORWARDED_FOR' => '192.168.1.50',
        ]);

        self::assertSame('192.168.1.50', $this->resolve($request));
    }

    public function test_peer_fallback_when_no_forwarded_header(): void
    {
        config()->set('security-defense.dashboard.trusted_proxies', ['127.0.0.1', '::1']);

        $request = Request::create('/security-defense', 'GET', [], [], [], [
            'REMOTE_ADDR' => '127.0.0.1',
        ]);

        self::assertSame('127.0.0.1', $this->resolve($request));
    }
}
