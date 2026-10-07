<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Concerns;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Mixudev\SecurityDefense\Middleware\RequestThreatScanner;

/**
 * Shared route registration for adversarial WAF tests.
 *
 * Every adversarial test MUST exercise the real middleware on a real route.
 * Calling PayloadInjectionRule directly proves the signature exists, not that
 * the shipped request path reaches it.
 */
trait RegistersWafProbeRoute
{
    protected function registerWafProbeRoutes(): void
    {
        Route::middleware(RequestThreatScanner::class)->group(function (): void {
            Route::get('/adv/probe', static fn () => response()->json(['status' => 'ok']));
            Route::post('/adv/submit', static fn (Request $request) => response()->json([
                'status' => 'reached',
                'received' => $request->all(),
            ]));
            Route::post('/adv/raw', static fn () => response()->json(['status' => 'reached']));
        });

        Route::getRoutes()->refreshNameLookups();
        Route::getRoutes()->refreshActionLookups();
    }

    /**
     * Disable auto-jail so one blocked vector cannot quarantine the IP used by
     * the next assertion inside the same test.
     */
    protected function withoutAutoJail(): void
    {
        config()->set('security-defense.middleware.quarantine.auto_jail_on_critical', false);
        config()->set('security-defense.middleware.quarantine.whitelist', []);
    }

    /**
     * @return array{status: int, body: string}
     */
    protected function probeGet(string $query, string $ip = '198.18.0.1'): array
    {
        $response = $this->withServerVariables(['REMOTE_ADDR' => $ip])
            ->get('/adv/probe?' . http_build_query(['q' => $query]));

        return ['status' => $response->getStatusCode(), 'body' => $response->getContent() ?: ''];
    }

    /**
     * @return array{status: int, body: string}
     */
    protected function probeForm(string $field, string $value, string $ip = '198.18.0.1'): array
    {
        $response = $this->withServerVariables(['REMOTE_ADDR' => $ip])
            ->post('/adv/submit', [$field => $value]);

        return ['status' => $response->getStatusCode(), 'body' => $response->getContent() ?: ''];
    }

    /**
     * @return array{status: int, body: string}
     */
    protected function probeJson(string $field, string $value, string $ip = '198.18.0.1'): array
    {
        $response = $this->withServerVariables(['REMOTE_ADDR' => $ip])
            ->postJson('/adv/submit', [$field => $value]);

        return ['status' => $response->getStatusCode(), 'body' => $response->getContent() ?: ''];
    }
}
