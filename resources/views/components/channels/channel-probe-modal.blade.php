@props([
    'channelsStatus' => [],
])

<!-- Channel Diagnostic Probes Modal Component -->
<div id="channelProbeModal" class="fixed inset-0 z-50 hidden bg-black/75 backdrop-blur-sm flex items-center justify-center p-4 transition-opacity duration-200">
    <div class="bg-white dark:bg-[#141416] border border-zinc-300 dark:border-zinc-800 rounded-2xl max-w-3xl w-full overflow-hidden shadow-2xl transform transition-all">
        <!-- Modal Header -->
        <div class="px-6 py-4 border-b border-zinc-200 dark:border-zinc-800 flex items-center justify-between bg-zinc-50 dark:bg-[#18181b]">
            <div class="flex items-center space-x-3">
                <div class="w-9 h-9 rounded-lg bg-emerald-600 flex items-center justify-center text-white shadow-xs">
                    <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z" />
                    </svg>
                </div>
                <div>
                    <h3 class="text-sm font-bold text-zinc-900 dark:text-zinc-100 uppercase tracking-wider">Channel Diagnostic Probe Center</h3>
                    <p class="text-xs text-zinc-500 dark:text-zinc-400">Safely test notification channels and webhook endpoints with simulated payload verification.</p>
                </div>
            </div>
            <button type="button" onclick="closeChannelProbeModal()" class="w-8 h-8 rounded-lg flex items-center justify-center text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200 hover:bg-zinc-100 dark:hover:bg-zinc-800 transition cursor-pointer text-lg font-bold">
                &times;
            </button>
        </div>

        <!-- Modal Body: Compact Probe Cards Grid -->
        <div class="p-6 space-y-4 max-h-[70vh] overflow-y-auto">
            <!-- Probe All Banner -->
            <div class="p-3.5 rounded-xl bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-300/80 dark:border-emerald-800/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div>
                    <h4 class="text-xs font-bold text-emerald-950 dark:text-emerald-200">Simultaneous Diagnostics Broadcast</h4>
                    <p class="text-[11px] text-emerald-700 dark:text-emerald-400">Trigger simulated test pings concurrently across all enabled notification gateways.</p>
                </div>
                <form action="{{ route('security-defense.test-channel') }}" method="POST">
                    @csrf
                    <input type="hidden" name="channel" value="all">
                    <button type="submit" class="w-full sm:w-auto inline-flex items-center justify-center px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-bold transition cursor-pointer shadow-xs whitespace-nowrap">
                        <svg class="w-3.5 h-3.5 mr-1.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M6 12L3.269 3.126A59.768 59.768 0 0121.485 12 59.77 59.77 0 013.27 20.876L5.999 12zm0 0h7.5" />
                        </svg>
                        Probe All Active Channels
                    </button>
                </form>
            </div>

            <!-- Channel Cards Grid -->
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                @foreach($channelsStatus as $key => $status)
                    @php
                        $cKey = strtolower($key);
                        $enabled = $status['enabled'] ?? false;
                        $target = $status['target'] ?? 'None';
                        $cLabel = match($cKey) {
                            'webhook' => 'Custom Webhook',
                            'discord' => 'Discord Webhook',
                            'telegram' => 'Telegram Bot',
                            'mail' => 'Email Dispatch',
                            'database' => 'SIEM Database',
                            default => ucfirst($cKey),
                        };
                    @endphp

                    <div class="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-zinc-50/50 dark:bg-[#18181b] p-3.5 flex flex-col justify-between hover:border-zinc-300 dark:hover:border-zinc-700 transition">
                        <div>
                            <div class="flex items-center justify-between mb-2">
                                <div class="flex items-center space-x-2">
                                    <span class="font-bold text-xs text-zinc-800 dark:text-zinc-200">{{ $cLabel }}</span>
                                </div>

                                @if($enabled)
                                    <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-100 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-800">
                                        READY
                                    </span>
                                @else
                                    <span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-zinc-100 text-zinc-500 dark:bg-zinc-800 dark:text-zinc-400 border border-zinc-200 dark:border-zinc-700">
                                        OFF
                                    </span>
                                @endif
                            </div>

                            <div class="text-[10px] text-zinc-500 dark:text-zinc-400 mb-1 font-medium">Target Destination:</div>
                            <div class="p-2 rounded-lg bg-white dark:bg-[#101012] border border-zinc-200 dark:border-zinc-800 font-mono text-[11px] text-zinc-700 dark:text-zinc-300 truncate mb-3" title="{{ $target }}">
                                {{ $target ?: 'Not configured' }}
                            </div>
                        </div>

                        <!-- Single Channel Test Probe Form -->
                        <form action="{{ route('security-defense.test-channel') }}" method="POST">
                            @csrf
                            <input type="hidden" name="channel" value="{{ $cKey }}">
                            <button type="submit" class="w-full inline-flex items-center justify-center px-3 py-1.5 rounded-lg text-xs font-semibold bg-white hover:bg-zinc-100 dark:bg-[#202024] dark:hover:bg-[#28282c] text-zinc-800 dark:text-zinc-200 border border-zinc-200 dark:border-zinc-700 transition cursor-pointer shadow-xs">
                                <span>Send Test Probe</span>
                                <svg class="w-3 h-3 ml-1 text-zinc-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                    <path stroke-linecap="round" stroke-linejoin="round" d="M14 5l7 7m0 0l-7 7m7-7H3" />
                                </svg>
                            </button>
                        </form>
                    </div>
                @endforeach
            </div>
        </div>

        <!-- Modal Footer -->
        <div class="px-6 py-3 bg-zinc-50 dark:bg-[#18181b] border-t border-zinc-200 dark:border-zinc-800 flex justify-between items-center text-xs text-zinc-500 dark:text-zinc-400">
            <span class="text-[11px]">Probes are sent in non-intrusive sandbox format.</span>
            <button type="button" onclick="closeChannelProbeModal()" class="px-4 py-1.5 rounded-lg bg-zinc-200 hover:bg-zinc-300 dark:bg-[#27272a] dark:hover:bg-[#3f3f46] text-zinc-800 dark:text-zinc-200 font-semibold cursor-pointer transition">
                Close
            </button>
        </div>
    </div>
</div>

<script>
    function openChannelProbeModal() {
        const modal = document.getElementById('channelProbeModal');
        if (modal) modal.classList.remove('hidden');
    }

    function closeChannelProbeModal() {
        const modal = document.getElementById('channelProbeModal');
        if (modal) modal.classList.add('hidden');
    }

    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') closeChannelProbeModal();
    });
</script>
