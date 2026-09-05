@props([
    'current' => '30d',
])

@php
    $presets = [
        'today' => 'Today',
        '7d' => '7 Days',
        '30d' => '30 Days',
    ];
@endphp

<div class="flex flex-wrap items-center gap-2">
    <span class="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">Date Range:</span>
    <form method="GET" class="flex items-center gap-1">
        @foreach(request()->except(['range', 'page']) as $key => $value)
            @if(is_array($value))
                @foreach($value as $v)
                    <input type="hidden" name="{{ $key }}[]" value="{{ $v }}">
                @endforeach
            @else
                <input type="hidden" name="{{ $key }}" value="{{ $value }}">
            @endif
        @endforeach

        @foreach($presets as $value => $label)
            <button type="submit" name="range" value="{{ $value }}"
                class="px-2.5 py-1 rounded-lg text-[11px] font-semibold transition cursor-pointer border
                    {{ $current === $value
                        ? 'bg-zinc-900 text-white border-zinc-900 dark:bg-zinc-100 dark:text-zinc-900 dark:border-zinc-100'
                        : 'bg-white text-zinc-600 border-zinc-300 hover:bg-zinc-100 dark:bg-[#18181b] dark:text-zinc-300 dark:border-zinc-700 dark:hover:bg-zinc-800' }}">
                {{ $label }}
            </button>
        @endforeach
    </form>
</div>