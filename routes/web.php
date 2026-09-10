<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Mixudev\SecurityDefense\Http\Controllers\DashboardController;
use Mixudev\SecurityDefense\Http\Controllers\PortalController;
use Mixudev\SecurityDefense\Http\Controllers\TelegramWebhookController;
use Mixudev\SecurityDefense\Http\Middleware\EnsureLocalAccess;
use Mixudev\SecurityDefense\Support\OpaqueDashboardPathResolver;

// Dashboard Routes (Local Only)
if (config('security-defense.dashboard.enabled', true)) {
    $opaqueEnabled = (bool) config('security-defense.dashboard.opaque_path.enabled', false);
    $configuredPath = (string) config('security-defense.dashboard.path', 'security-defense');
    $path = OpaqueDashboardPathResolver::resolvePath($opaqueEnabled, $configuredPath);

    if ($opaqueEnabled) {
        Route::prefix($configuredPath)
            ->middleware(['web', EnsureLocalAccess::class])
            ->name('security-defense.portal.')
            ->group(function () {
                Route::get('/', [PortalController::class, 'index'])->name('index');
                Route::post('/enter', [PortalController::class, 'enter'])->name('enter');
            });
    }

    Route::prefix($path)
        ->middleware(['web', EnsureLocalAccess::class])
        ->name('security-defense.')
        ->group(function () {
            Route::get('/', [DashboardController::class, 'index'])->name('dashboard');
            Route::get('/data-audits', [DashboardController::class, 'dataAudits'])->name('data-audits');
            Route::get('/sessions', [DashboardController::class, 'sessionIntelligence'])->name('sessions');
            Route::get('/epistemic', [DashboardController::class, 'epistemic'])->name('epistemic');
            Route::post('/epistemic/feedback', [DashboardController::class, 'epistemicFeedback'])->name('epistemic.feedback');
            Route::post('/test-channel', [DashboardController::class, 'testChannel'])->name('test-channel');
            Route::post('/alerts/{alert}/acknowledge', [DashboardController::class, 'acknowledge'])->name('alerts.acknowledge');
            Route::post('/alerts/{alert}/resolve', [DashboardController::class, 'resolve'])->name('alerts.resolve');
            Route::post('/quarantine/pardon', [DashboardController::class, 'pardonIp'])->name('quarantine.pardon');
            Route::post('/quarantine/whitelist', [DashboardController::class, 'whitelistIp'])->name('quarantine.whitelist');
            Route::get('/live-events', [DashboardController::class, 'liveEvents'])->name('live-events');
            Route::post('/toggle-setting', [DashboardController::class, 'toggleSetting'])->name('toggle-setting');
        });
}

// Telegram Webhook Endpoint
if (config('security-defense.alerts.telegram.enabled', false) && config('security-defense.alerts.telegram.interactive.enabled', true)) {
    Route::post('security-defense/telegram/webhook', TelegramWebhookController::class)
        ->name('security-defense.telegram.webhook');
}
