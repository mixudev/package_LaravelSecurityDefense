@props([
    'name',
    'status',
])

@php
    $key = strtolower($name);
    $enabled = $status['enabled'] ?? false;
    $configured = $status['configured'] ?? false;
    $target = $status['target'] ?? 'None';

    $label = match($key) {
        'webhook' => 'Webhook',
        'discord' => 'Discord',
        'telegram' => 'Telegram',
        'mail' => 'Email',
        'database' => 'Database',
        default => ucfirst($key),
    };
@endphp

<div class="rounded-lg bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 p-3.5 flex flex-col justify-between hover:border-zinc-300 dark:hover:border-zinc-700 transition">
    <div>
        <div class="flex items-center justify-between mb-2.5">
            <div class="flex items-center space-x-2">
                @if($key === 'webhook')
                    <svg class="w-4 h-4 text-zinc-500 dark:text-zinc-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M13.828 10.172a4 4 0 010 5.656l-2 2a4 4 0 01-5.656-5.656l1.5-1.5M10.172 13.828a4 4 0 010-5.656l2-2a4 4 0 015.656 5.656l-1.5 1.5" /></svg>
                @elseif($key === 'discord')
                    <svg class="w-4 h-4 text-zinc-500 dark:text-zinc-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" /></svg>
                @elseif($key === 'telegram')
                    <svg class="w-4 h-4 text-zinc-500 dark:text-zinc-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 21a9 9 0 100-18 9 9 0 000 18zM9.5 12.5l1.8 1.8 3.2-3.6" /></svg>
                @elseif($key === 'mail')
                    <svg class="w-4 h-4 text-zinc-500 dark:text-zinc-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75" /></svg>
                @elseif($key === 'database')
                    <svg class="w-4 h-4 text-zinc-500 dark:text-zinc-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v6m3-3H9m6-6H9m12 0h.01M12 3c4.418 0 8 1.343 8 3s-3.582 3-8 3-8-1.343-8-3 3.582-3 8-3zm0 18c-4.418 0-8-1.343-8-3V6c0-1.657 3.582-3 8-3s8 1.343 8 3v9c0 1.657-3.582 3-8 3z" /></svg>
                @else
                    <svg class="w-4 h-4 text-zinc-500 dark:text-zinc-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                @endif
                <span class="font-bold text-xs uppercase tracking-wider text-zinc-800 dark:text-zinc-200">{{ $label }}</span>
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
        <div class="p-2 rounded bg-zinc-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800/80 font-mono text-[11px] text-zinc-700 dark:text-zinc-300 break-all mb-3 min-h-[38px] flex items-center" title="{{ $target }}">
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
