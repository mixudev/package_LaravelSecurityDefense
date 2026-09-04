@props([
    'name',
    'status',
])

@php
    $key = strtolower($name);
    $enabled = $status['enabled'] ?? false;
    $configured = $status['configured'] ?? false;
    $target = $status['target'] ?? 'None';

    $icon = match($key) {
        'webhook' => '🌐',
        'discord' => '💬',
        'telegram' => '✈️',
        'mail' => '✉️',
        'database' => '🗄️',
        default => '📡',
    };
@endphp

<div class="rounded-lg bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 p-3.5 flex flex-col justify-between hover:border-zinc-300 dark:hover:border-zinc-700 transition">
    <div>
        <div class="flex items-center justify-between mb-2.5">
            <div class="flex items-center space-x-1.5">
                <span class="text-sm">{{ $icon }}</span>
                <span class="font-bold text-xs uppercase tracking-wider text-zinc-800 dark:text-zinc-200">{{ $key }}</span>
            </div>

            @if($enabled)
                <span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800">
                    ACTIVE
                </span>
            @else
                <span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-zinc-100 dark:bg-zinc-800 text-zinc-500 dark:text-zinc-400 border border-zinc-200 dark:border-zinc-700">
                    OFF
                </span>
            @endif
        </div>

        <div class="text-[10px] text-zinc-500 dark:text-zinc-400 mb-1 font-medium">Endpoint / Recipient:</div>
        <div class="p-2 rounded bg-zinc-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800/80 font-mono text-[11px] text-zinc-700 dark:text-zinc-300 break-all mb-3 min-h-[38px] flex items-center">
            {{ $target ?: 'Not Set' }}
        </div>
    </div>

    <!-- Probe Button -->
    <form action="{{ route('security-defense.test-channel') }}" method="POST">
        @csrf
        <input type="hidden" name="channel" value="{{ $key }}">
        <button type="submit" class="w-full inline-flex items-center justify-center px-2.5 py-1.5 rounded-md text-xs font-semibold bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-800 dark:hover:bg-zinc-700 text-zinc-800 dark:text-zinc-200 border border-zinc-200 dark:border-zinc-700 transition cursor-pointer">
            <span>Test Probe</span>
            <svg class="w-3 h-3 ml-1 text-zinc-500 dark:text-zinc-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M14 5l7 7m0 0l-7 7m7-7H3" />
            </svg>
        </button>
    </form>
</div>
