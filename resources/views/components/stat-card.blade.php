@props([
    'title',
    'value',
    'subtitle' => null,
    'badge' => null,
    'badgeColor' => 'zinc', // 'zinc', 'rose', 'orange', 'emerald', 'cyan'
])

@php
    $badgeClasses = match($badgeColor) {
        'rose' => 'bg-rose-50 dark:bg-rose-950/60 text-rose-700 dark:text-rose-400 border-rose-200 dark:border-rose-800',
        'orange' => 'bg-orange-50 dark:bg-orange-950/60 text-orange-700 dark:text-orange-400 border-orange-200 dark:border-orange-800',
        'emerald' => 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800',
        'cyan' => 'bg-cyan-50 dark:bg-cyan-950/60 text-cyan-700 dark:text-cyan-400 border-cyan-200 dark:border-cyan-800',
        default => 'bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300 border-zinc-200 dark:border-zinc-700',
    };
@endphp

<div class="rounded-lg bg-white dark:bg-zinc-900 p-4 border border-zinc-200 dark:border-zinc-800 flex flex-col justify-between">
    <div class="flex items-center justify-between">
        <span class="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">{{ $title }}</span>
        @if($badge)
            <span class="px-1.5 py-0.5 rounded text-[10px] font-bold border {{ $badgeClasses }}">
                {{ $badge }}
            </span>
        @endif
    </div>
    <div class="mt-3 flex items-baseline justify-between">
        <span class="text-2xl font-bold tracking-tight text-zinc-900 dark:text-white font-mono">{{ $value }}</span>
        @if($subtitle)
            <span class="text-xs text-zinc-500 dark:text-zinc-400">{{ $subtitle }}</span>
        @endif
    </div>
</div>
