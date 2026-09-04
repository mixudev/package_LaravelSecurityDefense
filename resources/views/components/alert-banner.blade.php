@if(session('status_message'))
    <div class="p-3.5 rounded-lg bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-300 dark:border-emerald-800 text-emerald-800 dark:text-emerald-200 flex items-center justify-between text-xs font-medium">
        <div class="flex items-center space-x-2.5">
            <svg class="w-4 h-4 text-emerald-600 dark:text-emerald-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <span>{{ session('status_message') }}</span>
        </div>
    </div>
@endif

@if(session('error_message'))
    <div class="p-3.5 rounded-lg bg-rose-50 dark:bg-rose-950/40 border border-rose-300 dark:border-rose-800 text-rose-800 dark:text-rose-200 flex items-center justify-between text-xs font-medium">
        <div class="flex items-center space-x-2.5">
            <svg class="w-4 h-4 text-rose-600 dark:text-rose-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <span>{{ session('error_message') }}</span>
        </div>
    </div>
@endif

@if(session('test_results'))
    <div class="rounded-lg bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 p-4 space-y-3">
        <div class="flex items-center justify-between border-b border-zinc-100 dark:border-zinc-800/80 pb-2.5">
            <div class="flex items-center space-x-2">
                <span class="w-2 h-2 rounded-full bg-cyan-500"></span>
                <h3 class="text-xs font-bold uppercase tracking-wider text-zinc-700 dark:text-zinc-300">Channel Diagnostic Test Summary</h3>
            </div>
            <span class="text-[11px] text-zinc-400 font-mono">{{ now()->toTimeString() }}</span>
        </div>

        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
            @foreach(session('test_results') as $res)
                <div class="p-3 rounded-md border text-xs {{ $res['success'] ? 'bg-emerald-50/50 dark:bg-emerald-950/20 border-emerald-300 dark:border-emerald-800/60' : ($res['enabled'] ? 'bg-rose-50/50 dark:bg-rose-950/20 border-rose-300 dark:border-rose-800/60' : 'bg-zinc-50 dark:bg-zinc-900 border-zinc-200 dark:border-zinc-800') }}">
                    <div class="flex items-center justify-between mb-1.5">
                        <span class="font-bold uppercase tracking-wider text-zinc-800 dark:text-zinc-200 text-[11px]">{{ $res['channel'] }}</span>
                        @if($res['success'])
                            <span class="px-1.5 py-0.5 rounded text-[10px] font-bold bg-emerald-100 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-800">DELIVERED</span>
                        @elseif(!$res['enabled'])
                            <span class="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-zinc-100 dark:bg-zinc-800 text-zinc-500 dark:text-zinc-400">DISABLED</span>
                        @elseif(!$res['configured'])
                            <span class="px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-100 dark:bg-amber-950 text-amber-800 dark:text-amber-400 border border-amber-300 dark:border-amber-800">UNCONFIGURED</span>
                        @else
                            <span class="px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-100 dark:bg-rose-950 text-rose-800 dark:text-rose-400 border border-rose-300 dark:border-rose-800">FAILED</span>
                        @endif
                    </div>
                    <p class="text-zinc-600 dark:text-zinc-400 text-[11px] leading-relaxed">{{ $res['message'] }}</p>
                    @if(isset($res['latency_ms']))
                        <p class="text-[10px] font-mono text-zinc-500 dark:text-zinc-400 mt-1">Latency: {{ $res['latency_ms'] }} ms</p>
                    @endif
                </div>
            @endforeach
        </div>
    </div>
@endif
