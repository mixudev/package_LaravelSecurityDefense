<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Signature;

use Mixudev\SecurityDefense\Tests\Feature\Adversarial\Concerns\RegistersWafProbeRoute;

trait ConfiguresSignatureRules
{
    use RegistersWafProbeRoute;

    protected function setUpSignatureProbe(): void
    {
        $this->registerWafProbeRoutes();

        // Reload the package defaults so "default config" in this suite means
        // exactly what a host app that never publishes/overrides the package
        // config receives. Testbench's Laravel fixture ships a stale published
        // copy under vendor/orchestra/.../config/, and mergeConfigFrom lets an
        // already-loaded value win, which would silently mask package defaults.
        config()->set(
            'security-defense',
            require dirname(__DIR__, 4) . '/config/security-defense.php'
        );

        $this->withoutAutoJail();
        config()->set('security-defense.middleware.payload_scanner.enabled', true);
        config()->set('security-defense.middleware.payload_scanner.action', 'block');
    }

    protected function enableSignature(string $category): void
    {
        config()->set("security-defense.detection.rules.payload_injection.patterns.{$category}", true);
    }

    protected function enableSignatures(array $categories): void
    {
        foreach ($categories as $category) {
            $this->enableSignature($category);
        }
    }

    protected function assertBlocked(string $payload, string $category, int $line): void
    {
        $this->enableSignature($category);
        $result = $this->probeForm('payload', $payload, '198.18.'.$line.'.1');
        $this->assertSame(403, $result['status'], "{$category} bypassed: {$payload}");
    }
}
