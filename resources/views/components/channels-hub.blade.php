@props([
    'channelsStatus' => [],
])

<!-- Compact Notification Channels & Webhook Testing Hub -->
<section class="rounded-xl bg-white dark:bg-[#0f172a] border border-slate-200/90 dark:border-slate-800 p-3.5 sm:p-4 shadow-xs">
    <div class="flex flex-col md:flex-row md:items-center justify-between gap-3">
        <!-- Left: Summary and Channel Pills -->
        <div class="flex flex-col sm:flex-row sm:items-center gap-3">
            <div class="flex items-center space-x-2">
                <div class="w-7 h-7 rounded-lg bg-slate-100 dark:bg-slate-800 flex items-center justify-center text-slate-700 dark:text-slate-300">
                    <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0" />
                    </svg>
                </div>
                <div>
                    <h3 class="text-xs font-bold text-slate-900 dark:text-white uppercase tracking-wider">Alert Relays & Webhooks</h3>
                    <p class="text-[10px] text-slate-500 dark:text-slate-400">Multi-channel SIEM dispatch</p>
                </div>
            </div>

            <!-- Mini Status Indicators -->
            <div class="flex flex-wrap items-center gap-1.5 sm:border-l sm:border-slate-200 dark:sm:border-slate-800 sm:pl-3">
                @foreach($channelsStatus as $key => $status)
                    @php
                        $enabled = $status['enabled'] ?? false;
                        $label = match(strtolower($key)) {
                            'webhook' => 'Webhook',
                            'discord' => 'Discord',
                            'telegram' => 'Telegram',
                            'mail' => 'Email',
                            'database' => 'DB',
                            default => ucfirst($key),
                        };
                    @endphp
                    <span class="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-semibold border {{ $enabled ? 'bg-emerald-50 text-emerald-700 border-emerald-300 dark:bg-emerald-950/50 dark:text-emerald-400 dark:border-emerald-800' : 'bg-slate-100 text-slate-500 border-slate-200 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700' }}" title="{{ $status['target'] ?? 'Not configured' }}">
                        <span class="w-1.5 h-1.5 rounded-full {{ $enabled ? 'bg-emerald-500' : 'bg-slate-400' }}"></span>
                        <span>{{ $label }}</span>
                    </span>
                @endforeach
            </div>
        </div>

        <!-- Right: Actions (Compact Group) -->
        <div class="flex items-center space-x-2">
            <!-- Modal Trigger: Channel Diagnostics -->
            <button type="button" onclick="openChannelProbeModal()"
                    class="inline-flex items-center justify-center px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 dark:bg-slate-100 dark:hover:bg-white text-white dark:text-slate-900 text-xs font-bold transition cursor-pointer shadow-xs">
                <svg class="w-3.5 h-3.5 mr-1.5 text-amber-400 dark:text-amber-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z" />
                </svg>
                <span>Channel Probe Hub</span>
            </button>

            <!-- Quick Test All Trigger -->
            <form action="{{ route('security-defense.test-channel') }}" method="POST" class="inline">
                @csrf
                <input type="hidden" name="channel" value="all">
                <button type="submit"
                        class="inline-flex items-center justify-center px-2.5 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 border border-slate-200 dark:border-slate-700 text-xs font-semibold transition cursor-pointer"
                        title="Broadcast diagnostic ping to all enabled channels immediately">
                    <svg class="w-3.5 h-3.5 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M6 12L3.269 3.126A59.768 59.768 0 0121.485 12 59.77 59.77 0 013.27 20.876L5.999 12zm0 0h7.5" />
                    </svg>
                    <span>Test All</span>
                </button>
            </form>
        </div>
    </div>
</section>

<!-- Channel Diagnostic Probes Modal -->
<div id="channelProbeModal" class="fixed inset-0 z-50 hidden bg-slate-950/70 backdrop-blur-sm flex items-center justify-center p-4 transition-opacity duration-200">
    <div class="bg-white dark:bg-[#0f172a] border border-slate-200 dark:border-slate-800 rounded-2xl max-w-3xl w-full overflow-hidden shadow-2xl transform transition-all">
        <!-- Modal Header -->
        <div class="px-6 py-4 border-b border-slate-200/90 dark:border-slate-800 flex items-center justify-between bg-slate-50/70 dark:bg-slate-900/60">
            <div class="flex items-center space-x-3">
                <div class="w-9 h-9 rounded-lg bg-indigo-600 flex items-center justify-center text-white shadow-xs">
                    <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z" />
                    </svg>
                </div>
                <div>
                    <h3 class="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider">Channel Diagnostic Probe Center</h3>
                    <p class="text-xs text-slate-500 dark:text-slate-400">Safely test notification channels and webhook endpoints with simulated payload verification.</p>
                </div>
            </div>
            <button type="button" onclick="closeChannelProbeModal()" class="w-8 h-8 rounded-lg flex items-center justify-center text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition cursor-pointer text-lg font-bold">
                &times;
            </button>
        </div>

        <!-- Modal Body: Compact Probe Cards Grid -->
        <div class="p-6 space-y-4 max-h-[70vh] overflow-y-auto">
            <!-- Probe All Banner -->
            <div class="p-3.5 rounded-xl bg-indigo-50 dark:bg-indigo-950/40 border border-indigo-200 dark:border-indigo-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div>
                    <h4 class="text-xs font-bold text-indigo-950 dark:text-indigo-200">Simultaneous Diagnostics Broadcast</h4>
                    <p class="text-[11px] text-indigo-700 dark:text-indigo-400">Trigger simulated test pings concurrently across all enabled notification gateways.</p>
                </div>
                <form action="{{ route('security-defense.test-channel') }}" method="POST">
                    @csrf
                    <input type="hidden" name="channel" value="all">
                    <button type="submit" class="w-full sm:w-auto inline-flex items-center justify-center px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-bold transition cursor-pointer shadow-xs whitespace-nowrap">
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
                        $configured = $status['configured'] ?? false;
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

                    <div class="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/40 p-3.5 flex flex-col justify-between hover:border-slate-300 dark:hover:border-slate-700 transition">
                        <div>
                            <div class="flex items-center justify-between mb-2">
                                <div class="flex items-center space-x-2">
                                    @if($cKey === 'webhook')
                                        <svg class="w-4 h-4 text-indigo-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M13.828 10.172a4 4 0 010 5.656l-2 2a4 4 0 01-5.656-5.656l1.5-1.5M10.172 13.828a4 4 0 010-5.656l2-2a4 4 0 015.656 5.656l-1.5 1.5" /></svg>
                                    @elseif($cKey === 'discord')
                                        <svg class="w-4 h-4 text-indigo-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" /></svg>
                                    @elseif($cKey === 'telegram')
                                        <svg class="w-4 h-4 text-sky-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 21a9 9 0 100-18 9 9 0 000 18zM9.5 12.5l1.8 1.8 3.2-3.6" /></svg>
                                    @elseif($cKey === 'mail')
                                        <svg class="w-4 h-4 text-rose-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75" /></svg>
                                    @else
                                        <svg class="w-4 h-4 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v6m3-3H9m6-6H9m12 0h.01M12 3c4.418 0 8 1.343 8 3s-3.582 3-8 3-8-1.343-8-3 3.582-3 8-3zm0 18c-4.418 0-8-1.343-8-3V6c0-1.657 3.582-3 8-3s8 1.343 8 3v9c0 1.657-3.582 3-8 3z" /></svg>
                                    @endif
                                    <span class="font-bold text-xs text-slate-800 dark:text-slate-200">{{ $cLabel }}</span>
                                </div>

                                @if($enabled)
                                    <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-100 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-800">
                                        READY
                                    </span>
                                @else
                                    <span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400 border border-slate-200 dark:border-slate-700">
                                        OFF
                                    </span>
                                @endif
                            </div>

                            <div class="text-[10px] text-slate-500 dark:text-slate-400 mb-1 font-medium">Target Destination:</div>
                            <div class="p-2 rounded-lg bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 font-mono text-[11px] text-slate-700 dark:text-slate-300 truncate mb-3" title="{{ $target }}">
                                {{ $target ?: 'Not configured' }}
                            </div>
                        </div>

                        <!-- Single Channel Test Probe Form -->
                        <form action="{{ route('security-defense.test-channel') }}" method="POST">
                            @csrf
                            <input type="hidden" name="channel" value="{{ $cKey }}">
                            <button type="submit" class="w-full inline-flex items-center justify-center px-3 py-1.5 rounded-lg text-xs font-semibold bg-white hover:bg-slate-100 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 border border-slate-200 dark:border-slate-700 transition cursor-pointer shadow-xs">
                                <span>Send Test Probe</span>
                                <svg class="w-3 h-3 ml-1 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                    <path stroke-linecap="round" stroke-linejoin="round" d="M14 5l7 7m0 0l-7 7m7-7H3" />
                                </svg>
                            </button>
                        </form>
                    </div>
                @endforeach
            </div>
        </div>

        <!-- Modal Footer -->
        <div class="px-6 py-3 bg-slate-50 dark:bg-slate-900 border-t border-slate-200 dark:border-slate-800 flex justify-between items-center text-xs text-slate-500 dark:text-slate-400">
            <span class="text-[11px]">Probes are sent in non-intrusive sandbox format.</span>
            <button type="button" onclick="closeChannelProbeModal()" class="px-4 py-1.5 rounded-lg bg-slate-200 hover:bg-slate-300 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 font-semibold cursor-pointer transition">
                Close
            </button>
        </div>
    </div>
</div>

<script>
    function openChannelProbeModal() {
        const modal = document.getElementById('channelProbeModal');
        if (modal) {
            modal.classList.remove('hidden');
        }
    }

    function closeChannelProbeModal() {
        const modal = document.getElementById('channelProbeModal');
        if (modal) {
            modal.classList.add('hidden');
        }
    }

    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            closeChannelProbeModal();
        }
    });
</script>
