@props([
    'threatDistribution' => [],
])

@if(!empty($threatDistribution))
    @php
        $max = max($threatDistribution);
        $total = array_sum($threatDistribution);
    @endphp
    <section class="rounded-lg bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 p-4">
        <div class="flex items-center justify-between mb-3">
            <h3 class="text-xs font-bold uppercase tracking-wider text-zinc-600 dark:text-zinc-400">Attack Vector Prevalence</h3>
            <span class="text-[11px] text-zinc-400 dark:text-zinc-500">{{ count($threatDistribution) }} vectors</span>
        </div>
        <div class="space-y-2">
            @foreach($threatDistribution as $type => $count)
                @php
                    $width = $max > 0 ? round(($count / $max) * 100) : 0;
                    $pct = $total > 0 ? round(($count / $total) * 100) : 0;
                    $barColor = ($count === $max) ? 'bg-rose-500' : 'bg-zinc-700 dark:bg-zinc-300';
                @endphp
                <div class="flex items-center gap-3">
                    <span class="w-36 flex-shrink-0 truncate text-[11px] font-medium text-zinc-700 dark:text-zinc-300 capitalize" title="{{ str_replace('_', ' ', $type) }}">{{ str_replace('_', ' ', $type) }}</span>
                    <div class="flex-1 h-2 rounded-full bg-zinc-100 dark:bg-zinc-800 overflow-hidden">
                        <div class="h-full rounded-full {{ $barColor }}" style="width: {{ $width }}%"></div>
                    </div>
                    <span class="w-14 flex-shrink-0 text-right font-mono text-[10px] font-bold text-zinc-800 dark:text-zinc-200">{{ number_format($count) }} <span class="text-zinc-400 dark:text-zinc-500 font-normal">({{ $pct }}%)</span></span>
                </div>
            @endforeach
        </div>
    </section>
@endif
