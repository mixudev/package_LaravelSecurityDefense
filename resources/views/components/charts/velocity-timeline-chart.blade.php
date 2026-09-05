@props([
    'hourlyData' => ['labels' => [], 'totals' => [], 'criticals' => [], 'peak' => 0],
])

<!-- 24-Hour Incident Velocity Timeline Component -->
<div class="rounded-xl bg-white dark:bg-[#0f172a] border border-slate-200/90 dark:border-slate-800 p-4 sm:p-5 flex flex-col justify-between shadow-xs">
    <div class="flex items-center justify-between border-b border-slate-100 dark:border-slate-800/80 pb-3 mb-3">
        <div>
            <h3 class="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300 flex items-center space-x-2">
                <span>24-Hour Incident Velocity Timeline</span>
            </h3>
            <p class="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">Hourly attack distribution comparing general telemetry vs critical breaches.</p>
        </div>
        <div class="flex items-center space-x-3 text-[11px] font-mono">
            <div class="flex items-center space-x-1.5 text-indigo-600 dark:text-indigo-400">
                <span class="w-2.5 h-2.5 rounded-full bg-indigo-500"></span>
                <span class="font-medium">All Threats</span>
            </div>
            <div class="flex items-center space-x-1.5 text-rose-600 dark:text-rose-400">
                <span class="w-2.5 h-2.5 rounded-full bg-rose-500"></span>
                <span class="font-medium">Severe</span>
            </div>
        </div>
    </div>

    <!-- Canvas Container -->
    <div class="relative w-full h-64">
        <canvas id="threatVelocityChart"></canvas>
    </div>

    <div class="pt-3 border-t border-slate-100 dark:border-slate-800/80 flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400">
        <span>Peak Frequency: <strong class="font-mono text-slate-800 dark:text-slate-200">{{ $hourlyData['peak'] }} incidents/hr</strong></span>
        <span class="font-mono">Adaptive Window: 24h</span>
    </div>
</div>

<script>
    document.addEventListener('DOMContentLoaded', function() {
        if (typeof Chart === 'undefined') return;

        const isDark = document.documentElement.classList.contains('dark');
        const gridColor = isDark ? 'rgba(51, 65, 85, 0.35)' : 'rgba(226, 232, 240, 0.8)';
        const textColor = isDark ? '#94a3b8' : '#64748b';

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
                            borderColor: '#6366f1',
                            backgroundColor: isDark ? 'rgba(99, 102, 241, 0.15)' : 'rgba(99, 102, 241, 0.10)',
                            fill: true,
                            tension: 0.35,
                            borderWidth: 2,
                            pointRadius: 2,
                            pointHoverRadius: 5,
                            pointBackgroundColor: '#6366f1',
                        },
                        {
                            label: 'Critical / High',
                            data: criticals,
                            borderColor: '#f43f5e',
                            backgroundColor: isDark ? 'rgba(244, 63, 94, 0.15)' : 'rgba(244, 63, 94, 0.10)',
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
                            backgroundColor: isDark ? '#0f172a' : '#1e293b',
                            titleColor: '#ffffff',
                            bodyColor: '#e2e8f0',
                            borderColor: isDark ? '#334155' : '#475569',
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
