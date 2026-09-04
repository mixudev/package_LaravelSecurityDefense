@props([
    'threatDistribution' => [],
])

@if(!empty($threatDistribution))
    <section class="rounded-lg bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 p-4">
        <div class="flex items-center justify-between mb-3">
            <h3 class="text-xs font-bold uppercase tracking-wider text-zinc-600 dark:text-zinc-400">Attack Vector Prevalence</h3>
            <span class="text-[11px] text-zinc-400 dark:text-zinc-500">Historical Distribution</span>
        </div>
        <div class="flex flex-wrap gap-2">
            @foreach($threatDistribution as $type => $count)
                <div class="inline-flex items-center px-2.5 py-1 rounded-md bg-zinc-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 text-xs">
                    <span class="font-medium text-zinc-700 dark:text-zinc-300 capitalize">{{ str_replace('_', ' ', $type) }}</span>
                    <span class="ml-2 px-1.5 py-0.2 rounded bg-zinc-200 dark:bg-zinc-800 text-zinc-800 dark:text-zinc-200 font-mono text-[10px] font-bold">{{ $count }}</span>
                </div>
            @endforeach
        </div>
    </section>
@endif
