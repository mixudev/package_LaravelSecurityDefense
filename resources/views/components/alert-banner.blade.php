@if(session('status_message'))
    <div id="statusAlertBanner" class="rounded-xl bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-300 dark:border-emerald-800 text-emerald-900 dark:text-emerald-200 p-4 flex items-center justify-between shadow-xs transition-all duration-300">
        <div class="flex items-center space-x-3">
            <div class="w-8 h-8 rounded-lg bg-emerald-100 dark:bg-emerald-900/60 flex items-center justify-center text-emerald-700 dark:text-emerald-300 flex-shrink-0">
                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
            </div>
            <div>
                <h4 class="text-xs font-bold uppercase tracking-wider text-emerald-800 dark:text-emerald-300">Operation Successful</h4>
                <p class="text-xs text-emerald-700 dark:text-emerald-300 mt-0.5">{{ session('status_message') }}</p>
            </div>
        </div>
        <button type="button" onclick="document.getElementById('statusAlertBanner').remove()" class="text-emerald-600 hover:text-emerald-900 dark:text-emerald-400 dark:hover:text-emerald-100 p-1.5 rounded-lg hover:bg-emerald-100 dark:hover:bg-emerald-900/40 transition cursor-pointer">
            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
        </button>
    </div>
@endif

@if(session('error_message'))
    <div id="errorAlertBanner" class="rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-300 dark:border-rose-800 text-rose-900 dark:text-rose-200 p-4 flex items-center justify-between shadow-xs transition-all duration-300">
        <div class="flex items-center space-x-3">
            <div class="w-8 h-8 rounded-lg bg-rose-100 dark:bg-rose-900/60 flex items-center justify-center text-rose-700 dark:text-rose-300 flex-shrink-0">
                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                </svg>
            </div>
            <div>
                <h4 class="text-xs font-bold uppercase tracking-wider text-rose-800 dark:text-rose-300">Defense Action Warning</h4>
                <p class="text-xs text-rose-700 dark:text-rose-300 mt-0.5">{{ session('error_message') }}</p>
            </div>
        </div>
        <button type="button" onclick="document.getElementById('errorAlertBanner').remove()" class="text-rose-600 hover:text-rose-900 dark:text-rose-400 dark:hover:text-rose-100 p-1.5 rounded-lg hover:bg-rose-100 dark:hover:bg-rose-900/40 transition cursor-pointer">
            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
        </button>
    </div>
@endif

@if(session('test_results'))
    @php
        $results = session('test_results');
        $successful = count(array_filter($results, fn($r) => $r['success'] ?? false));
        $total = count($results);
    @endphp
    <div id="diagnosticResultsPanel" class="rounded-xl bg-white dark:bg-[#121214] border border-zinc-300/80 dark:border-zinc-800 p-5 space-y-4 shadow-sm">
        <div class="flex items-center justify-between border-b border-zinc-100 dark:border-zinc-800/80 pb-3">
            <div class="flex items-center space-x-3">
                <div class="w-8 h-8 rounded-lg bg-emerald-600 flex items-center justify-center text-white">
                    <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                </div>
                <div>
                    <div class="flex items-center space-x-2">
                        <h3 class="text-xs font-bold uppercase tracking-wider text-zinc-800 dark:text-zinc-200">Channel Diagnostic Test Summary</h3>
                        <span class="px-2 py-0.5 rounded text-[10px] font-bold {{ $successful === $total ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300' : 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300' }}">
                            {{ $successful }}/{{ $total }} Delivered
                        </span>
                    </div>
                    <p class="text-[11px] text-zinc-500 dark:text-zinc-400 mt-0.5">Real-time gateway connectivity status and payload delivery latency.</p>
                </div>
            </div>

            <div class="flex items-center space-x-2">
                <span class="text-[11px] text-zinc-400 font-mono hidden sm:inline">{{ now()->toTimeString() }}</span>
                <button type="button" onclick="document.getElementById('diagnosticResultsPanel').remove()" class="text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200 p-1.5 rounded-lg hover:bg-zinc-100 dark:hover:bg-zinc-800 transition cursor-pointer">
                    <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
                    </svg>
                </button>
            </div>
        </div>

        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            @foreach($results as $res)
                <div class="p-3.5 rounded-xl border text-xs transition-all {{ $res['success'] ? 'bg-emerald-50/60 dark:bg-emerald-950/20 border-emerald-300 dark:border-emerald-800/60' : ($res['enabled'] ? 'bg-rose-50/60 dark:bg-rose-950/20 border-rose-300 dark:border-rose-800/60' : 'bg-zinc-50 dark:bg-[#18181b] border-zinc-200 dark:border-zinc-800') }}">
                    <div class="flex items-center justify-between mb-2">
                        <span class="font-bold uppercase tracking-wider text-zinc-800 dark:text-zinc-200 text-xs">{{ $res['channel'] }}</span>
                        @if($res['success'])
                            <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-100 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-800">
                                DELIVERED
                            </span>
                        @elseif(!$res['enabled'])
                            <span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-zinc-100 dark:bg-zinc-800 text-zinc-500 dark:text-zinc-400 border border-zinc-200 dark:border-zinc-700">
                                DISABLED
                            </span>
                        @elseif(!$res['configured'])
                            <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-100 dark:bg-amber-950 text-amber-800 dark:text-amber-400 border border-amber-300 dark:border-amber-800">
                                UNCONFIGURED
                            </span>
                        @else
                            <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-100 dark:bg-rose-950 text-rose-800 dark:text-rose-400 border border-rose-300 dark:border-rose-800">
                                FAILED
                            </span>
                        @endif
                    </div>
                    <p class="text-zinc-600 dark:text-zinc-300 text-xs leading-relaxed">{{ $res['message'] }}</p>
                    @if(isset($res['latency_ms']))
                        <div class="mt-2 pt-2 border-t border-zinc-200/60 dark:border-zinc-800/60 flex items-center justify-between text-[10px] font-mono text-zinc-500 dark:text-zinc-400">
                            <span>Network Latency:</span>
                            <span class="font-bold text-zinc-700 dark:text-zinc-300">{{ $res['latency_ms'] }} ms</span>
                        </div>
                    @endif
                </div>
            @endforeach
        </div>
    </div>
@endif
