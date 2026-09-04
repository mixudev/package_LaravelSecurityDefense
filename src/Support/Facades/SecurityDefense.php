<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Support\Facades;

use Illuminate\Support\Facades\Facade;
use Mixudev\SecurityDefense\Contracts\ThreatDetector;
use Mixudev\SecurityDefense\Contracts\ThreatSource;
use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\DTO\SecurityThreat;
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Services\AlertDispatcher;
use Mixudev\SecurityDefense\Services\SecurityDefenseManager;

/**
 * @method static array<SecurityThreat> record(ThreatSource|array<string, mixed> $source)
 * @method static array<SecurityThreat> processEvent(SecurityEvent $event)
 * @method static bool resolveAlert(int|SecurityAlert $alert)
 * @method static ThreatDetector detector()
 * @method static AlertDispatcher dispatcher()
 *
 * @see SecurityDefenseManager
 */
class SecurityDefense extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return SecurityDefenseManager::class;
    }
}
