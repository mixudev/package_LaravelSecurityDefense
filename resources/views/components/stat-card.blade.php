@props([
    'title',
    'value',
    'subtitle' => null,
    'badge' => null,
    'badgeColor' => 'slate', // 'slate', 'rose', 'orange', 'emerald', 'cyan', 'indigo'
])

@php
    $badgeClasses = match($badgeColor) {
        'rose' => 'bg-rose-50 dark:bg-rose-950/60 text-rose-700 dark:text-rose-400 border-rose-200 dark:border-rose-800',
        'orange' => 'bg-orange-50 dark:bg-orange-950/60 text-orange-700 dark:text-orange-400 border-orange-200 dark:border-orange-800',
        'emerald' => 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800',
        'cyan' => 'bg-cyan-50 dark:bg-cyan-950/60 text-cyan-700 dark:text-cyan-400 border-cyan-200 dark:border-cyan-800',
        'indigo' => 'bg-indigo-50 dark:bg-indigo-950/60 text-indigo-700 dark:text-indigo-400 border-indigo-200 dark:border-indigo-800',
        default => 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-700',
    };
@endphp

<div class="rounded-xl bg-white dark:bg-[#0f172a] p-4 sm:p-5 border border-slate-200/90 dark:border-slate-800 flex flex-col justify-between shadow-xs hover:border-slate-300 dark:hover:border-slate-700 transition">
    <div class="flex items-center justify-between">
        <span class="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">{{ $title }}</span>
        @if($badge)
            <span class="px-2 py-0.5 rounded text-[10px] font-bold border {{ $badgeClasses }}">
                {{ $badge }}
            </span>
        @endif
    </div>
    <div class="mt-3 flex items-baseline justify-between">
        <span class="text-2xl sm:text-3xl font-extrabold tracking-tight text-slate-900 dark:text-white font-mono">{{ $value }}</span>
        @if($subtitle)
            <span class="text-xs text-slate-500 dark:text-slate-400 font-medium">{{ $subtitle }}</span>
        @endif
    </div>
</div>
