<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Contracts;

use Mixudev\SecurityDefense\Models\SecurityAlert;

/**
 * Contract for alert notification delivery channels.
 */
interface AlertChannel
{
    /**
     * Unique identifier of the alert channel (e.g., 'database', 'telegram', 'discord', 'webhook').
     */
    public function identifier(): string;

    /**
     * Check if the channel is enabled in package configuration.
     */
    public function isEnabled(): bool;

    /**
     * Check if the channel has valid credentials/parameters configured.
     */
    public function isConfigured(): bool;

    /**
     * Deliver the security alert through this channel.
     *
     * @param SecurityAlert $alert
     * @return bool True if successfully dispatched, false otherwise.
     */
    public function send(SecurityAlert $alert): bool;
}
