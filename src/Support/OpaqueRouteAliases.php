<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Support;

/** Non-descriptive, stable dashboard route segments. */
final class OpaqueRouteAliases
{
    /** @var array<string, string> */
    private const MAP = [
        'security-defense.dashboard' => 'a7k2',
        'security-defense.data-audits' => 'm4q8',
        'security-defense.sessions' => 'r9v3',
        'security-defense.epistemic' => 't6x1',
        'security-defense.epistemic.feedback' => 't6x1/f',
        'security-defense.test-channel' => 'c3p5',
        'security-defense.alerts.acknowledge' => 'n8d4/ack',
        'security-defense.alerts.resolve' => 'n8d4/res',
        'security-defense.quarantine.pardon' => 'q5b2/p',
        'security-defense.quarantine.whitelist' => 'q5b2/w',
        'security-defense.live-events' => 'l2h7',
        'security-defense.toggle-setting' => 'g6s9',
    ];

    public static function path(string $routeName): string
    {
        return self::MAP[$routeName] ?? throw new \InvalidArgumentException('Unknown dashboard route alias.');
    }
}
