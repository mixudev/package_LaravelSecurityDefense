@props([
    'threatDistribution' => [],
])

@php
    $maxVectorCount = !empty($threatDistribution) ? max($threatDistribution) : 0;
    $totalVectorCount = !empty($threatDistribution) ? array_sum($threatDistribution) : 0;
@endphp

<!-- Attack Vector Prevalence & Donut Breakdown -->
<div class="h-full w-full flex flex-col justify-between rounded-xl bg-white dark:bg-[#121214] border border-zinc-300/80 dark:border-zinc-800 p-4 sm:p-5 shadow-xs">
    <!-- Header -->
    <div class="flex items-center justify-between border-b border-zinc-100 dark:border-zinc-800/80 pb-3 mb-3">
        <div>
            <h3 class="text-xs font-bold uppercase tracking-wider text-zinc-800 dark:text-zinc-200">
                Attack Vector Prevalence
            </h3>
            <p class="text-[11px] text-zinc-500 dark:text-zinc-400 mt-0.5">Top threat categories categorized by signature rules.</p>
        </div>
        <span class="text-[11px] font-mono px-2 py-0.5 rounded bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400 font-semibold">
            {{ count($threatDistribution) }} Vectors
        </span>
    </div>

    <!-- Donut Canvas & Bar Breakdown (Flex child matching height) -->
    <div class="w-full my-auto py-1">
        @if(!empty($threatDistribution))
            <div class="grid grid-cols-1 sm:grid-cols-12 gap-3 items-center">
                <div class="sm:col-span-5 relative flex items-center justify-center h-44 sm:h-48">
                    <canvas id="threatVectorDonut"></canvas>
                </div>

                <div class="sm:col-span-7 space-y-2 max-h-48 overflow-y-auto pr-1">
                    @foreach($threatDistribution as $type => $count)
                        @php
                            $width = $maxVectorCount > 0 ? round(($count / $maxVectorCount) * 100) : 0;
                            $pct = $totalVectorCount > 0 ? round(($count / $totalVectorCount) * 100) : 0;
                            $barColor = ($count === $maxVectorCount) ? 'bg-rose-500' : 'bg-emerald-500 dark:bg-emerald-400';
                        @endphp
                        <div class="group">
                            <div class="flex items-center justify-between text-[11px] mb-1">
                                <span class="font-semibold text-zinc-700 dark:text-zinc-300 capitalize truncate" title="{{ str_replace('_', ' ', $type) }}">
                                    {{ str_replace('_', ' ', $type) }}
                                </span>
                                <span class="font-mono text-zinc-800 dark:text-zinc-200 font-bold">
                                    {{ number_format($count) }} <span class="text-zinc-400 font-normal">({{ $pct }}%)</span>
                                </span>
                            </div>
                            <div class="w-full h-1.5 rounded-full bg-zinc-100 dark:bg-zinc-800 overflow-hidden">
                                <div class="h-full rounded-full {{ $barColor }} transition-all duration-500" style="width: {{ $width }}%"></div>
                            </div>
                        </div>
                    @endforeach
                </div>
            </div>
        @else
            <div class="py-12 text-center text-zinc-400 dark:text-zinc-500 text-xs">
                No threat vector telemetry recorded yet. All traffic remains within safety margins.
            </div>
        @endif
    </div>

    <!-- Footer -->
    <div class="pt-3 border-t border-zinc-100 dark:border-zinc-800/80 text-[11px] text-zinc-500 dark:text-zinc-400 flex justify-between">
        <span>Total Correlated Violations: <strong class="font-mono text-zinc-800 dark:text-zinc-200">{{ number_format($totalVectorCount) }}</strong></span>
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
                                '#10b981', // Emerald
                                '#f59e0b', // Amber
                                '#f43f5e', // Rose
                                '#a855f7', // Violet
                                '#14b8a6', // Teal
                                '#ec4899', // Pink
                                '#84cc16', // Lime
                                '#71717a', // Zinc
                            ],
                            borderWidth: isDark ? 2 : 1.5,
                            borderColor: isDark ? '#121214' : '#ffffff',
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
                                backgroundColor: isDark ? '#18181b' : '#27272a',
                                titleColor: '#ffffff',
                                bodyColor: '#e4e4e7',
                                padding: 8,
                            }
                        }
                    }
                });
            }
        }
    });
</script>
