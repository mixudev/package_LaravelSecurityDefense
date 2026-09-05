@props([
    'title',
    'value',
    'subtitle' => null,
    'badge' => null,
    'badgeColor' => 'zinc', // 'zinc', 'rose', 'orange', 'emerald', 'amber', 'purple'
])

@php
    $badgeClasses = match($badgeColor) {
        'rose' => 'bg-rose-50 dark:bg-rose-950/60 text-rose-700 dark:text-rose-400 border-rose-300 dark:border-rose-800',
        'orange' => 'bg-orange-50 dark:bg-orange-950/60 text-orange-700 dark:text-orange-400 border-orange-300 dark:border-orange-800',
        'emerald' => 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400 border-emerald-300 dark:border-emerald-800',
        'amber' => 'bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-400 border-amber-300 dark:border-amber-800',
        'purple' => 'bg-purple-50 dark:bg-purple-950/60 text-purple-700 dark:text-purple-400 border-purple-300 dark:border-purple-800',
        default => 'bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300 border-zinc-300 dark:border-zinc-700',
    };
@endphp

<div class="rounded-xl bg-white dark:bg-[#121214] p-4 sm:p-5 border border-zinc-300/80 dark:border-zinc-800 flex flex-col justify-between shadow-xs hover:border-zinc-400/80 dark:hover:border-zinc-700 transition">
    <div class="flex items-center justify-between">
        <span class="text-[11px] font-bold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">{{ $title }}</span>
        @if($badge)
            <span class="px-2 py-0.5 rounded text-[10px] font-bold border {{ $badgeClasses }}">
                {{ $badge }}
            </span>
        @endif
    </div>
    <div class="mt-3 flex items-baseline justify-between">
        <span class="text-2xl sm:text-3xl font-extrabold tracking-tight text-zinc-900 dark:text-zinc-100 font-mono">{{ $value }}</span>
        @if($subtitle)
            <span class="text-xs text-zinc-500 dark:text-zinc-400 font-medium">{{ $subtitle }}</span>
        @endif
    </div>
</div>
