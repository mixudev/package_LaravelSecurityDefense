@props([
    'hourlyData' => ['labels' => [], 'totals' => [], 'criticals' => [], 'peak' => 0],
])

<!-- 24-Hour Incident Velocity Timeline Component -->
<div class="h-full w-full flex flex-col justify-between rounded-xl bg-white dark:bg-[#121214] border border-zinc-300/80 dark:border-zinc-800 p-4 sm:p-5 shadow-xs">
    <!-- Header -->
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-zinc-100 dark:border-zinc-800/80 pb-3 mb-3">
        <div>
            <h3 class="text-xs font-bold uppercase tracking-wider text-zinc-800 dark:text-zinc-200 flex items-center space-x-2">
                <span>24-Hour Incident Velocity Timeline</span>
            </h3>
            <p class="text-[11px] text-zinc-500 dark:text-zinc-400 mt-0.5">Hourly attack distribution comparing general telemetry vs critical breaches.</p>
        </div>
        <div class="flex items-center space-x-3 text-[11px] font-mono">
            <div class="flex items-center space-x-1.5 text-emerald-600 dark:text-emerald-400">
                <span class="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
                <span class="font-medium">All Threats</span>
            </div>
            <div class="flex items-center space-x-1.5 text-rose-600 dark:text-rose-400">
                <span class="w-2.5 h-2.5 rounded-full bg-rose-500"></span>
                <span class="font-medium">Severe</span>
            </div>
        </div>
    </div>

    <!-- Canvas Container (Flex child matching height) -->
    <div class="relative w-full h-52 sm:h-56 my-auto">
        <canvas id="threatVelocityChart"></canvas>
    </div>

    <!-- Footer -->
    <div class="pt-3 border-t border-zinc-100 dark:border-zinc-800/80 flex items-center justify-between text-[11px] text-zinc-500 dark:text-zinc-400">
        <span>Peak Frequency: <strong class="font-mono text-zinc-800 dark:text-zinc-200">{{ $hourlyData['peak'] }} incidents/hr</strong></span>
        <span class="font-mono">Adaptive Window: 24h</span>
    </div>
</div>

<script>
    document.addEventListener('DOMContentLoaded', function() {
        if (typeof Chart === 'undefined') return;

        const isDark = document.documentElement.classList.contains('dark');
        const gridColor = isDark ? 'rgba(39, 39, 42, 0.7)' : 'rgba(228, 228, 231, 0.8)';
        const textColor = isDark ? '#a1a1aa' : '#71717a';

        const velocityCtx = document.getElementById('threatVelocityChart');
        if (velocityCtx) {
            const labels = @json($hourlyData['labels'] ?? []);
            const totals = @json($hourlyData['totals'] ?? []);
            const criticals = @json($hourlyData['criticals'] ?? []);

            new Chart(velocityCtx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: 'Total Incidents',
                            data: totals,
                            borderColor: '#10b981',
                            backgroundColor: isDark ? 'rgba(16, 185, 129, 0.12)' : 'rgba(16, 185, 129, 0.08)',
                            fill: true,
                            tension: 0.35,
                            borderWidth: 2,
                            pointRadius: 2,
                            pointHoverRadius: 5,
                            pointBackgroundColor: '#10b981',
                        },
                        {
                            label: 'Critical / High',
                            data: criticals,
                            borderColor: '#f43f5e',
                            backgroundColor: isDark ? 'rgba(244, 63, 94, 0.12)' : 'rgba(244, 63, 94, 0.08)',
                            fill: true,
                            tension: 0.35,
                            borderWidth: 2,
                            pointRadius: 2,
                            pointHoverRadius: 5,
                            pointBackgroundColor: '#f43f5e',
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    interaction: {
                        mode: 'index',
                        intersect: false,
                    },
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            backgroundColor: isDark ? '#18181b' : '#27272a',
                            titleColor: '#ffffff',
                            bodyColor: '#e4e4e7',
                            borderColor: isDark ? '#27272a' : '#3f3f46',
                            borderWidth: 1,
                            padding: 10,
                            boxPadding: 4,
                            usePointStyle: true,
                        }
                    },
                    scales: {
                        x: {
                            grid: { color: gridColor, drawBorder: false },
                            ticks: {
                                color: textColor,
                                font: { size: 10, family: "'JetBrains Mono', monospace" },
                                maxRotation: 0,
                                autoSkip: true,
                                maxTicksLimit: 8,
                            }
                        },
                        y: {
                            beginAtZero: true,
                            grid: { color: gridColor, drawBorder: false },
                            ticks: {
                                color: textColor,
                                font: { size: 10, family: "'JetBrains Mono', monospace" },
                                precision: 0,
                            }
                        }
                    }
                }
            });
        }
    });
</script>
