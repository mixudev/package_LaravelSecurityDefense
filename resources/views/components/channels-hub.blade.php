@props([
    'channelsStatus' => [],
])

<!-- Compact Notification Channels & Webhook Testing Hub -->
<section class="rounded-xl bg-white dark:bg-[#121214] border border-zinc-300/80 dark:border-zinc-800 p-3.5 sm:p-4 shadow-xs">
    <div class="flex flex-col md:flex-row md:items-center justify-between gap-3">
        <!-- Left: Summary and Channel Pills -->
        <div class="flex flex-col sm:flex-row sm:items-center gap-3">
            <div class="flex items-center space-x-2">
                <div class="w-7 h-7 rounded-lg bg-zinc-100 dark:bg-[#18181b] flex items-center justify-center text-zinc-700 dark:text-zinc-300 border border-zinc-200 dark:border-zinc-700">
                    <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0" />
                    </svg>
                </div>
                <div>
                    <h3 class="text-xs font-bold text-zinc-900 dark:text-zinc-100 uppercase tracking-wider">Alert Relays & Webhooks</h3>
                    <p class="text-[10px] text-zinc-500 dark:text-zinc-400">Multi-channel SIEM dispatch</p>
                </div>
            </div>

            <!-- Mini Status Indicators -->
            <div class="flex flex-wrap items-center gap-1.5 sm:border-l sm:border-zinc-200 dark:sm:border-zinc-800 sm:pl-3">
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
                    <span class="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-semibold border {{ $enabled ? 'bg-emerald-50 text-emerald-700 border-emerald-300 dark:bg-emerald-950/50 dark:text-emerald-400 dark:border-emerald-800' : 'bg-zinc-100 text-zinc-500 border-zinc-200 dark:bg-zinc-800 dark:text-zinc-400 dark:border-zinc-700' }}" title="{{ $status['target'] ?? 'Not configured' }}">
                        <span class="w-1.5 h-1.5 rounded-full {{ $enabled ? 'bg-emerald-500' : 'bg-zinc-400' }}"></span>
                        <span>{{ $label }}</span>
                    </span>
                @endforeach
            </div>
        </div>

        <!-- Right: Actions (Compact Group) -->
        <div class="flex items-center space-x-2">
            <!-- Modal Trigger: Channel Diagnostics -->
            <button type="button" onclick="openChannelProbeModal()"
                    class="inline-flex items-center justify-center px-3 py-1.5 rounded-lg bg-zinc-900 hover:bg-zinc-800 dark:bg-zinc-100 dark:hover:bg-white text-white dark:text-zinc-900 text-xs font-bold transition cursor-pointer shadow-xs">
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
                        class="inline-flex items-center justify-center px-2.5 py-1.5 rounded-lg bg-zinc-100 hover:bg-zinc-200 dark:bg-[#1f1f23] dark:hover:bg-[#2a2a30] text-zinc-700 dark:text-zinc-200 border border-zinc-300 dark:border-zinc-700 text-xs font-semibold transition cursor-pointer"
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

<!-- Channel Diagnostic Probes Modal Component -->
@include('security-defense::components.channels.channel-probe-modal', ['channelsStatus' => $channelsStatus])
