<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Mixudev\SecurityDefense\Http\Controllers\DashboardController;
use Mixudev\SecurityDefense\Http\Controllers\TelegramWebhookController;
use Mixudev\SecurityDefense\Http\Middleware\EnsureLocalAccess;

// Dashboard Routes (Local Only)
if (config('security-defense.dashboard.enabled', true)) {
    $path = (string) config('security-defense.dashboard.path', 'security-defense');

    Route::prefix($path)
        ->middleware(['web', EnsureLocalAccess::class])
        ->name('security-defense.')
        ->group(function () {
            Route::get('/', [DashboardController::class, 'index'])->name('dashboard');
            Route::get('/data-audits', [DashboardController::class, 'dataAudits'])->name('data-audits');
            Route::get('/sessions', [DashboardController::class, 'sessionIntelligence'])->name('sessions');
            Route::post('/test-channel', [DashboardController::class, 'testChannel'])->name('test-channel');
            Route::post('/alerts/{alert}/acknowledge', [DashboardController::class, 'acknowledge'])->name('alerts.acknowledge');
            Route::post('/alerts/{alert}/resolve', [DashboardController::class, 'resolve'])->name('alerts.resolve');
            Route::post('/quarantine/pardon', [DashboardController::class, 'pardonIp'])->name('quarantine.pardon');
        });
}

// Telegram Webhook Endpoint
if (config('security-defense.alerts.telegram.enabled', false) && config('security-defense.alerts.telegram.interactive.enabled', true)) {
    Route::post('security-defense/telegram/webhook', TelegramWebhookController::class)
        ->name('security-defense.telegram.webhook');
}
