<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Mixudev\SecurityDefense\Http\Controllers\DashboardController;
use Mixudev\SecurityDefense\Http\Controllers\PortalController;
use Mixudev\SecurityDefense\Http\Controllers\TelegramWebhookController;
use Mixudev\SecurityDefense\Http\Middleware\EnsureLocalAccess;
use Mixudev\SecurityDefense\Http\Middleware\ValidateOpaqueDashboardPath;
use Mixudev\SecurityDefense\Support\OpaqueRouteAliases;
use Mixudev\SecurityDefense\Support\DashboardCapability;

// Dashboard Routes (Local Only)
if (config('security-defense.dashboard.enabled', true)) {
    $opaqueEnabled = (bool) config('security-defense.dashboard.opaque_path.enabled', false);
    $configuredPath = (string) config('security-defense.dashboard.path', 'security-defense');

    if ($opaqueEnabled) {
        Route::prefix($configuredPath)
            ->middleware(['web', EnsureLocalAccess::class])
            ->name('security-defense.portal.')
            ->group(function () {
                Route::get('/', [PortalController::class, 'index'])->name('index');
                Route::post('/enter', [PortalController::class, 'enter'])->name('enter');
            });
    }

    $dashboardPrefix = $opaqueEnabled ? '{opaque}' : $configuredPath;
    $segment = static fn (string $routeName, string $legacy): string => $opaqueEnabled ? OpaqueRouteAliases::path($routeName) : $legacy;
    $alertAction = static fn (string $routeName, string $legacy): string => $opaqueEnabled ? OpaqueRouteAliases::path($routeName) . '/{alert}' : $legacy;
    $dashboardMiddleware = $opaqueEnabled
        ? ['web', ValidateOpaqueDashboardPath::class, EnsureLocalAccess::class]
        : ['web', EnsureLocalAccess::class];

    Route::prefix($dashboardPrefix)
        ->where(['opaque' => DashboardCapability::ROUTE_PATTERN])
        ->middleware($dashboardMiddleware)
        ->name('security-defense.')
        ->group(function () use ($segment, $alertAction) {
            Route::get('/', [DashboardController::class, 'index'])->name('dashboard');
            Route::get('/' . $segment('security-defense.data-audits', 'data-audits'), [DashboardController::class, 'dataAudits'])->name('data-audits');
            Route::get('/' . $segment('security-defense.sessions', 'sessions'), [DashboardController::class, 'sessionIntelligence'])->name('sessions');
            Route::get('/' . $segment('security-defense.epistemic', 'epistemic'), [DashboardController::class, 'epistemic'])->name('epistemic');
            Route::post('/' . $segment('security-defense.epistemic.feedback', 'epistemic/feedback'), [DashboardController::class, 'epistemicFeedback'])->name('epistemic.feedback');
            Route::post('/' . $segment('security-defense.test-channel', 'test-channel'), [DashboardController::class, 'testChannel'])->name('test-channel');
            Route::post('/' . $alertAction('security-defense.alerts.acknowledge', 'alerts/{alert}/acknowledge'), [DashboardController::class, 'acknowledge'])->name('alerts.acknowledge');
            Route::post('/' . $alertAction('security-defense.alerts.resolve', 'alerts/{alert}/resolve'), [DashboardController::class, 'resolve'])->name('alerts.resolve');
            Route::post('/' . $segment('security-defense.quarantine.pardon', 'quarantine/pardon'), [DashboardController::class, 'pardonIp'])->name('quarantine.pardon');
            Route::post('/' . $segment('security-defense.quarantine.whitelist', 'quarantine/whitelist'), [DashboardController::class, 'whitelistIp'])->name('quarantine.whitelist');
            Route::get('/' . $segment('security-defense.live-events', 'live-events'), [DashboardController::class, 'liveEvents'])->name('live-events');
            Route::post('/' . $segment('security-defense.toggle-setting', 'toggle-setting'), [DashboardController::class, 'toggleSetting'])->name('toggle-setting');
        });
}

// Telegram Webhook Endpoint
if (config('security-defense.alerts.telegram.enabled', false) && config('security-defense.alerts.telegram.interactive.enabled', true)) {
    Route::post('security-defense/telegram/webhook', TelegramWebhookController::class)
        ->name('security-defense.telegram.webhook');
}
