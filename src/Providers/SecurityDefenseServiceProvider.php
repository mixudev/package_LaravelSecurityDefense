<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Providers;

use Illuminate\Support\ServiceProvider;
use Mixudev\SecurityDefense\Channels\DatabaseChannel;
use Mixudev\SecurityDefense\Channels\DiscordChannel;
use Mixudev\SecurityDefense\Channels\TelegramChannel;
use Mixudev\SecurityDefense\Channels\WebhookChannel;
use Mixudev\SecurityDefense\Contracts\AlertDeduplicatorInterface;
use Mixudev\SecurityDefense\Contracts\ThreatDetector;
use Mixudev\SecurityDefense\Detection\AnomalyDetector;
use Mixudev\SecurityDefense\Rules\BruteForceRule;
use Mixudev\SecurityDefense\Rules\CredentialStuffingRule;
use Mixudev\SecurityDefense\Rules\DistributedSprayRule;
use Mixudev\SecurityDefense\Rules\ImpossibleTravelRule;
use Mixudev\SecurityDefense\Rules\PayloadInjectionRule;
use Mixudev\SecurityDefense\Rules\RateLimitBypassRule;
use Mixudev\SecurityDefense\Services\AlertDeduplicator;
use Mixudev\SecurityDefense\Services\AlertDispatcher;
use Mixudev\SecurityDefense\Services\SecurityDefenseManager;

/**
 * Service provider for registering mixudev/security-defense components in Laravel container.
 */
class SecurityDefenseServiceProvider extends ServiceProvider
{
    /**
     * Register any package services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../../config/security-defense.php', 'security-defense');

        // Bind Alert Deduplicator
        $this->app->singleton(AlertDeduplicatorInterface::class, AlertDeduplicator::class);

        // Bind Detection Rules
        $this->app->singleton(BruteForceRule::class);
        $this->app->singleton(CredentialStuffingRule::class);
        $this->app->singleton(DistributedSprayRule::class);
        $this->app->singleton(RateLimitBypassRule::class);
        $this->app->singleton(PayloadInjectionRule::class);
        $this->app->singleton(ImpossibleTravelRule::class);

        // Bind Detection Engine with default active rules
        $this->app->singleton(ThreatDetector::class, function ($app) {
            return new AnomalyDetector([
                $app->make(BruteForceRule::class),
                $app->make(CredentialStuffingRule::class),
                $app->make(DistributedSprayRule::class),
                $app->make(RateLimitBypassRule::class),
                $app->make(PayloadInjectionRule::class),
                $app->make(ImpossibleTravelRule::class),
            ]);
        });

        // Bind Alert Channels
        $this->app->singleton(DatabaseChannel::class);
        $this->app->singleton(TelegramChannel::class);
        $this->app->singleton(DiscordChannel::class);
        $this->app->singleton(WebhookChannel::class);

        // Bind Alert Dispatcher
        $this->app->singleton(AlertDispatcher::class, function ($app) {
            return new AlertDispatcher(
                deduplicator: $app->make(AlertDeduplicatorInterface::class),
                channels: [
                    $app->make(DatabaseChannel::class),
                    $app->make(TelegramChannel::class),
                    $app->make(DiscordChannel::class),
                    $app->make(WebhookChannel::class),
                ]
            );
        });

        // Bind Primary Coordinator Manager
        $this->app->singleton(SecurityDefenseManager::class, function ($app) {
            return new SecurityDefenseManager(
                detector: $app->make(ThreatDetector::class),
                dispatcher: $app->make(AlertDispatcher::class)
            );
        });

        $this->app->alias(SecurityDefenseManager::class, 'security-defense');
    }

    /**
     * Bootstrap package services, migrations, and publishables.
     */
    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            // Publish Configuration
            $this->publishes([
                __DIR__ . '/../../config/security-defense.php' => config_path('security-defense.php'),
            ], 'security-defense-config');

            // Publish Migrations
            $this->publishes([
                __DIR__ . '/../../database/migrations/' => database_path('migrations'),
            ], 'security-defense-migrations');
        }

        // Load Package Migrations directly
        $this->loadMigrationsFrom(__DIR__ . '/../../database/migrations');
    }
}
