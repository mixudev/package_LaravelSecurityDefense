<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Channels;

use Mixudev\SecurityDefense\Contracts\AlertChannel;
use Mixudev\SecurityDefense\Models\SecurityAlert;

/**
 * Mandatory database channel for persisting security alerts.
 */
class DatabaseChannel implements AlertChannel
{
    public function identifier(): string
    {
        return 'database';
    }

    public function isEnabled(): bool
    {
        return (bool) config('security-defense.alerts.database.enabled', true);
    }

    public function isConfigured(): bool
    {
        return true;
    }

    /**
     * Persist the alert to the database.
     */
    public function send(SecurityAlert $alert): bool
    {
        if (!$this->isEnabled()) {
            return false;
        }

        if ($alert->exists) {
            return true;
        }

        return $alert->save();
    }
}
