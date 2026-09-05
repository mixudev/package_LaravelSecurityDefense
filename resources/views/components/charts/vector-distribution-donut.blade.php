@props([
    'threatDistribution' => [],
])

@php
    $maxVectorCount = !empty($threatDistribution) ? max($threatDistribution) : 0;
    $totalVectorCount = !empty($threatDistribution) ? array_sum($threatDistribution) : 0;
@endphp

<!-- Attack Vector Prevalence & Donut Breakdown -->
<div class="rounded-xl bg-white dark:bg-[#0f172a] border border-slate-200/90 dark:border-slate-800 p-4 sm:p-5 flex flex-col justify-between shadow-xs">
    <div class="flex items-center justify-between border-b border-slate-100 dark:border-slate-800/80 pb-3 mb-3">
        <div>
            <h3 class="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">
                Attack Vector Prevalence
            </h3>
            <p class="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">Top threat categories categorized by signature rules.</p>
        </div>
        <span class="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 font-semibold">
            {{ count($threatDistribution) }} Vectors
        </span>
    </div>

    <!-- Donut Canvas & Bar Breakdown -->
    @if(!empty($threatDistribution))
        <div class="grid grid-cols-1 sm:grid-cols-12 gap-3 items-center">
            <div class="sm:col-span-5 relative flex items-center justify-center h-44">
                <canvas id="threatVectorDonut"></canvas>
            </div>

            <div class="sm:col-span-7 space-y-2 max-h-48 overflow-y-auto pr-1">
                @foreach($threatDistribution as $type => $count)
                    @php
                        $width = $maxVectorCount > 0 ? round(($count / $maxVectorCount) * 100) : 0;
                        $pct = $totalVectorCount > 0 ? round(($count / $totalVectorCount) * 100) : 0;
                        $barColor = ($count === $maxVectorCount) ? 'bg-rose-500' : 'bg-indigo-500 dark:bg-indigo-400';
                    @endphp
                    <div class="group">
                        <div class="flex items-center justify-between text-[11px] mb-1">
                            <span class="font-semibold text-slate-700 dark:text-slate-300 capitalize truncate" title="{{ str_replace('_', ' ', $type) }}">
                                {{ str_replace('_', ' ', $type) }}
                            </span>
                            <span class="font-mono text-slate-800 dark:text-slate-200 font-bold">
                                {{ number_format($count) }} <span class="text-slate-400 font-normal">({{ $pct }}%)</span>
                            </span>
                        </div>
                        <div class="w-full h-1.5 rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden">
                            <div class="h-full rounded-full {{ $barColor }} transition-all duration-500" style="width: {{ $width }}%"></div>
                        </div>
                    </div>
                @endforeach
            </div>
        </div>
    @else
        <div class="py-12 text-center text-slate-400 dark:text-slate-500 text-xs">
            No threat vector telemetry recorded yet. All traffic remains within safety margins.
        </div>
    @endif

    <div class="pt-3 border-t border-slate-100 dark:border-slate-800/80 text-[11px] text-slate-500 dark:text-slate-400 flex justify-between">
        <span>Total Correlated Violations: <strong class="font-mono text-slate-800 dark:text-slate-200">{{ number_format($totalVectorCount) }}</strong></span>
    </div>
</div>

<script>
    document.addEventListener('DOMContentLoaded', function() {
        if (typeof Chart === 'undefined') return;

        const isDark = document.documentElement.classList.contains('dark');
        const donutCtx = document.getElementById('threatVectorDonut');
        if (donutCtx) {
            const rawDist = @json($threatDistribution ?? []);
            const keys = Object.keys(rawDist).map(k => k.replace(/_/g, ' '));
            const vals = Object.values(rawDist);

            if (vals.length > 0) {
                new Chart(donutCtx, {
                    type: 'doughnut',
                    data: {
                        labels: keys,
                        datasets: [{
                            data: vals,
                            backgroundColor: [
                                '#6366f1', '#f43f5e', '#0ea5e9', '#10b981',
                                '#f59e0b', '#8b5cf6', '#ec4899', '#64748b',
                            ],
                            borderWidth: isDark ? 2 : 1.5,
                            borderColor: isDark ? '#0f172a' : '#ffffff',
                            hoverOffset: 4,
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        cutout: '72%',
                        plugins: {
                            legend: { display: false },
                            tooltip: {
                                backgroundColor: isDark ? '#0f172a' : '#1e293b',
                                titleColor: '#ffffff',
                                bodyColor: '#e2e8f0',
                                padding: 8,
                            }
                        }
                    }
                });
            }
        }
    });
</script>
