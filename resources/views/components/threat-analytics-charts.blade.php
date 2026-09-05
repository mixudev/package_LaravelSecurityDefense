@props([
    'hourlyData' => ['labels' => [], 'totals' => [], 'criticals' => [], 'peak' => 0],
    'threatDistribution' => [],
    'postureScore' => 100,
])

@php
    $postureLabel = match(true) {
        $postureScore >= 90 => 'OPTIMAL',
        $postureScore >= 75 => 'GUARDED',
        $postureScore >= 50 => 'ELEVATED',
        default => 'CRITICAL',
    };

    $postureBadge = match(true) {
        $postureScore >= 90 => 'bg-emerald-50 text-emerald-700 border-emerald-300 dark:bg-emerald-950/60 dark:text-emerald-400 dark:border-emerald-800',
        $postureScore >= 75 => 'bg-teal-50 text-teal-700 border-teal-300 dark:bg-teal-950/60 dark:text-teal-400 dark:border-teal-800',
        $postureScore >= 50 => 'bg-amber-50 text-amber-700 border-amber-300 dark:bg-amber-950/60 dark:text-amber-400 dark:border-amber-800',
        default => 'bg-rose-50 text-rose-700 border-rose-300 dark:bg-rose-950/60 dark:text-rose-400 dark:border-rose-800',
    };
@endphp

<!-- Real-time Threat Intelligence & Analytics Grid -->
<div class="space-y-4">
    <!-- Analytics Header & Cache Health Bar -->
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 px-1">
        <div class="flex items-center space-x-3">
            <div class="p-2 rounded-lg bg-emerald-600 text-white shadow-xs">
                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M3.75 3v11.25A2.25 2.25 0 006 16.5h2.25M3.75 3h-1.5m1.5 0h16.5m0 0h1.5m-1.5 0v11.25A2.25 2.25 0 0118 16.5h-2.25m-7.5 0h7.5m-7.5 0l-1 3m8.5-3l1 3m0 0l.5 1.5m-.5-1.5h-9.5m0 0l-.5 1.5m.75-9l3-3 2.25 2.25L15 7.5" />
                </svg>
            </div>
            <div>
                <h2 class="text-sm font-bold text-zinc-900 dark:text-zinc-100 tracking-tight">
                    Threat Velocity & Adaptive Telemetry Analytics
                </h2>
                <p class="text-xs text-zinc-500 dark:text-zinc-400">Continuous 24-hour vector correlation and proactive defense readiness.</p>
            </div>
        </div>

        <div class="flex items-center space-x-2">
            <!-- Defensive Posture Chip -->
            <div class="inline-flex items-center space-x-2 px-3 py-1.5 rounded-lg border text-xs font-semibold {{ $postureBadge }} shadow-xs">
                <span class="w-2 h-2 rounded-full {{ $postureScore >= 75 ? 'bg-emerald-500 animate-pulse' : 'bg-rose-500 animate-ping' }}"></span>
                <span>Defense Posture: {{ $postureScore }}% &bull; {{ $postureLabel }}</span>
            </div>

            <!-- Optimized Cache Refresher -->
            <a href="{{ request()->fullUrlWithQuery(['refresh' => 1]) }}"
               class="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-white hover:bg-zinc-50 dark:bg-[#18181b] dark:hover:bg-[#202024] text-zinc-700 dark:text-zinc-300 border border-zinc-300/80 dark:border-zinc-700 text-xs font-semibold transition cursor-pointer shadow-xs"
               title="Bypass cached aggregations and query real-time SQLite/MySQL tables directly">
                <svg class="w-3.5 h-3.5 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99" />
                </svg>
                <span>Live Refresh</span>
            </a>
        </div>
    </div>

    <!-- Dual Charts Row: Stretched matching height on desktop, fully responsive on mobile -->
    <div class="grid grid-cols-1 lg:grid-cols-12 gap-4 items-stretch">
        <div class="lg:col-span-7 flex flex-col">
            @include('security-defense::components.charts.velocity-timeline-chart', ['hourlyData' => $hourlyData])
        </div>
        <div class="lg:col-span-5 flex flex-col">
            @include('security-defense::components.charts.vector-distribution-donut', ['threatDistribution' => $threatDistribution])
        </div>
    </div>

    <!-- Active Defensive Subsystems Grid -->
    @include('security-defense::components.charts.active-shields-grid')
</div>
