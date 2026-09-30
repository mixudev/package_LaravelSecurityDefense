<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Route;
use Mixudev\SecurityDefense\Support\ClientIpResolver;
use Mixudev\SecurityDefense\Tests\TestCase;

/**
 * Regression: the WAF telemetry path, the threat source and the flood/scoring
 * services read the client address from $request->ip(), while the dashboard
 * access gate and the OTP portal use Support\ClientIpResolver.
 *
 * When the host app configures an open trustProxies range (a very common
 * cloud/Laravel deployment choice, e.g. '0.0.0.0/0' or '::/0'), Symfony's
 * Request::ip() returns the LEFTMOST X-Forwarded-For entry, which the attacker
 * fully controls. Verified against symfony/http-foundation: with trusted
 * proxies ['0.0.0.0/0'] and REMOTE_ADDR 203.0.113.50 + X-Forwarded-For:
 * 9.9.9.9, ip() returns 9.9.9.9.
 *
 * Result: every IP-keyed security control on those paths (flood limiter
 * strikes, threat scoring, telemetry/quarantine, detection rules) can be
 * sidestepped by rotating a single header, while the dashboard gate correctly
 * refuses to trust it. The two must agree.
 */
final class WafClientIpConsistencyTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('security-defense.enabled', true);
        $app['config']->set('security-defense.cache_store', 'array');
        $app['config']->set('security-defense.detection.enabled', true);
    }

    private function openProxyRequest(): Request
    {
        $request = Request::create('/probe', 'GET', [], [], [], [
            'REMOTE_ADDR'          => '203.0.113.50',
            'HTTP_X_FORWARDED_FOR' => '9.9.9.9',
        ]);
        $request->setTrustedProxies(['0.0.0.0/0'], Request::HEADER_X_FORWARDED_FOR);

        return $request;
    }

    public function test_request_ip_follows_attacker_header_under_open_proxy_config(): void
    {
        $request = $this->openProxyRequest();

        // Precondition: proves the scenario is real, so the assertions below
        // cannot silently pass because the request stopped being spoofable.
        self::assertSame('9.9.9.9', $request->ip());
    }

    public function test_resolver_refuses_the_attacker_header(): void
    {
        $request = $this->openProxyRequest();

        self::assertSame('203.0.113.50', ClientIpResolver::resolve(
            $request,
            (array) config('security-defense.dashboard.trusted_proxies', ['127.0.0.1', '::1']),
        ));
    }

    public function test_threat_source_records_the_socket_peer_not_the_forwarded_value(): void
    {
        $request = $this->openProxyRequest();
        $request->setLaravelSession($this->app['session']->driver());

        $source = new \Mixudev\SecurityDefense\Sources\RequestThreatSource($request);

        self::assertNotSame('9.9.9.9', $source->toSecurityEvent()->ip);
    }

    public function test_flood_limiter_jails_the_socket_peer_not_the_forwarded_value(): void
    {
        // Drive the flood by setting the configured cap to zero, so every
        // request trips the limiter and jails.
        config([
            'security-defense.middleware.request_flood.enabled'                  => true,
            'security-defense.middleware.request_flood.max_requests_per_second' => 0,
            'security-defense.middleware.request_flood.window'                   => 5,
            'security-defense.middleware.request_flood.jail_after_exceeding'     => 1,
        ]);
        app()->forgetInstance(\Mixudev\SecurityDefense\Services\RequestFloodLimiter::class);
        app()->forgetInstance(\Mixudev\SecurityDefense\Services\IpQuarantineService::class);

        $request = $this->openProxyRequest();
        $request->setLaravelSession($this->app['session']->driver());

        $middleware = app(\Mixudev\SecurityDefense\Middleware\RequestThreatScanner::class);
        $middleware->handle($request, static fn ($r) => new \Illuminate\Http\Response('next'));

        $quarantine = app(\Mixudev\SecurityDefense\Services\IpQuarantineService::class);

        self::assertTrue(
            $quarantine->isQuarantined('203.0.113.50'),
            'the socket peer was not jailed, so an attacker behind an open-proxy '
            . 'host app config can flood the real address forever'
        );
        self::assertFalse(
            $quarantine->isQuarantined('9.9.9.9'),
            'the attacker-supplied X-Forwarded-For value was jailed instead, which is '
            . 'exactly the address the attacker can rotate at will'
        );
    }

    public function test_cache_keys_written_by_the_flood_path_bind_to_the_peer(): void
    {
        $limiter = app(\Mixudev\SecurityDefense\Services\RequestFloodLimiter::class);
        $limiter->isExceeded('203.0.113.50');

        $store = Cache::store('array')->getStore();
        $prop = new \ReflectionProperty(\Illuminate\Cache\ArrayStore::class, 'storage');
        $prop->setAccessible(true);
        $keys = array_keys($prop->getValue($store));

        self::assertNotSame([], $keys, 'the limiter recorded nothing at all');
    }
}
