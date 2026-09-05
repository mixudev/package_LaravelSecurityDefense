@props([
    'alerts',
    'filters' => [],
])

<section class="rounded-xl bg-white dark:bg-[#121214] border border-zinc-300/80 dark:border-zinc-800 p-4 sm:p-5 space-y-4 shadow-xs">
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div class="flex items-center space-x-3">
            <div class="w-8 h-8 rounded-lg bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200 dark:border-emerald-800 flex items-center justify-center text-emerald-600 dark:text-emerald-400 flex-shrink-0">
                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M3.75 12h16.5m-16.5 3.75h16.5M3.75 19.5h16.5M5.625 4.5h12.75a1.875 1.875 0 010 3.75H5.625a1.875 1.875 0 010-3.75z" />
                </svg>
            </div>
            <div>
                <h2 class="text-sm font-bold text-zinc-900 dark:text-zinc-100 tracking-tight flex items-center space-x-2">
                    <span>Security Incident Correlated Telemetry</span>
                </h2>
                <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">Real-time correlated telemetry records and forensic investigation queue.</p>
            </div>
        </div>

        <!-- Filters Form -->
        <form method="GET" class="flex flex-wrap items-center gap-2">
            <select name="status" onchange="this.form.submit()" class="bg-white dark:bg-[#18181b] border border-zinc-300 dark:border-zinc-700 text-zinc-700 dark:text-zinc-300 text-xs rounded-lg px-3 py-1.5 focus:ring-2 focus:ring-emerald-500/20 focus:outline-none">
                <option value="">All Statuses</option>
                <option value="new" {{ request('status') === 'new' ? 'selected' : '' }}>New</option>
                <option value="acknowledged" {{ request('status') === 'acknowledged' ? 'selected' : '' }}>Acknowledged</option>
                <option value="resolved" {{ request('status') === 'resolved' ? 'selected' : '' }}>Resolved</option>
            </select>

            <select name="severity" onchange="this.form.submit()" class="bg-white dark:bg-[#18181b] border border-zinc-300 dark:border-zinc-700 text-zinc-700 dark:text-zinc-300 text-xs rounded-lg px-3 py-1.5 focus:ring-2 focus:ring-emerald-500/20 focus:outline-none">
                <option value="">All Severities</option>
                <option value="critical" {{ request('severity') === 'critical' ? 'selected' : '' }}>Critical</option>
                <option value="high" {{ request('severity') === 'high' ? 'selected' : '' }}>High</option>
                <option value="medium" {{ request('severity') === 'medium' ? 'selected' : '' }}>Medium</option>
                <option value="low" {{ request('severity') === 'low' ? 'selected' : '' }}>Low</option>
            </select>

            @if(request()->hasAny(['status', 'severity', 'threat_type']))
                <a href="{{ route('security-defense.dashboard') }}" class="text-xs text-zinc-500 hover:text-emerald-600 dark:hover:text-emerald-400 px-2 py-1 transition font-medium">Reset</a>
            @endif
        </form>
    </div>

    <!-- Table -->
    <div class="overflow-x-auto rounded-lg border border-zinc-200 dark:border-zinc-800">
        <table class="min-w-full divide-y divide-zinc-200 dark:divide-zinc-800 text-left text-xs">
            <thead class="bg-zinc-50 dark:bg-[#18181b] font-bold text-zinc-600 dark:text-zinc-400 uppercase tracking-wider text-[10px]">
                <tr>
                    <th class="px-4 py-3">Severity</th>
                    <th class="px-4 py-3">Threat Type</th>
                    <th class="px-4 py-3">Fingerprint</th>
                    <th class="px-4 py-3">Detected</th>
                    <th class="px-4 py-3">Status</th>
                    <th class="px-4 py-3">Telemetry</th>
                    <th class="px-4 py-3 text-right">Actions</th>
                </tr>
            </thead>
            <tbody class="divide-y divide-zinc-200 dark:divide-zinc-800/80 bg-white dark:bg-[#121214]">
                @forelse($alerts as $alert)
                    @php
                        $sev = strtolower($alert->severity);
                        $sevBadge = match($sev) {
                            'critical' => 'bg-rose-50 text-rose-700 border-rose-300 dark:bg-rose-950/60 dark:text-rose-400 dark:border-rose-800',
                            'high' => 'bg-orange-50 text-orange-700 border-orange-300 dark:bg-orange-950/60 dark:text-orange-400 dark:border-orange-800',
                            'medium' => 'bg-amber-50 text-amber-700 border-amber-300 dark:bg-amber-950/60 dark:text-amber-400 dark:border-amber-800',
                            default => 'bg-zinc-100 text-zinc-700 border-zinc-300 dark:bg-zinc-800 dark:text-zinc-300 dark:border-zinc-700',
                        };
                        $sevDot = match($sev) {
                            'critical' => 'bg-rose-500',
                            'high' => 'bg-orange-500',
                            'medium' => 'bg-amber-500',
                            default => 'bg-zinc-400',
                        };
                    @endphp
                    <tr class="hover:bg-zinc-50/70 dark:hover:bg-zinc-800/40 transition">
                        <!-- Severity -->
                        <td class="px-4 py-3 whitespace-nowrap">
                            <span class="inline-flex items-center space-x-1.5 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border {{ $sevBadge }}">
                                <span class="w-1.5 h-1.5 rounded-full {{ $sevDot }}" aria-hidden="true"></span>
                                <span>{{ $alert->severity }}</span>
                            </span>
                        </td>

                        <!-- Threat Type -->
                        <td class="px-4 py-3">
                            <div class="font-bold text-zinc-800 dark:text-zinc-200 capitalize text-xs">
                                {{ str_replace('_', ' ', $alert->threat_type) }}
                            </div>
                            <div class="text-[10px] text-zinc-500 dark:text-zinc-400 font-mono">
                                {{ $alert->rule_identifier ?? 'custom' }}
                            </div>
                        </td>

                        <!-- Fingerprint -->
                        <td class="px-4 py-3 whitespace-nowrap">
                            <code class="px-2 py-0.5 rounded bg-zinc-100 dark:bg-[#18181b] border border-zinc-200 dark:border-zinc-800 text-[10px] text-zinc-700 dark:text-zinc-300 font-mono">
                                {{ substr($alert->fingerprint, 0, 12) }}...
                            </code>
                        </td>

                        <!-- Detected At -->
                        <td class="px-4 py-3 whitespace-nowrap text-zinc-500 dark:text-zinc-400 text-[11px]">
                            {{ $alert->created_at ? $alert->created_at->diffForHumans() : 'Just now' }}
                        </td>

                        <!-- Status -->
                        <td class="px-4 py-3 whitespace-nowrap">
                            @if($alert->status === 'new')
                                <span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-rose-50 text-rose-700 border border-rose-300 dark:bg-rose-950/40 dark:text-rose-400 dark:border-rose-900">NEW</span>
                            @elseif($alert->status === 'acknowledged')
                                <span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-amber-50 text-amber-700 border border-amber-300 dark:bg-amber-950/40 dark:text-amber-400 dark:border-amber-900">ACK</span>
                            @else
                                <span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-300 dark:bg-emerald-950/40 dark:text-emerald-400 dark:border-emerald-900">RESOLVED</span>
                            @endif
                        </td>

                        <!-- Telemetry Inspect -->
                        <td class="px-4 py-3 whitespace-nowrap">
                            <button type="button" onclick="showMetadataModal({{ $alert->id }}, '{{ e(json_encode($alert->metadata ?? [], JSON_HEX_APOS | JSON_HEX_QUOT)) }}')" class="inline-flex items-center px-2.5 py-1 rounded-lg bg-zinc-100 hover:bg-zinc-200 dark:bg-[#202024] dark:hover:bg-[#28282c] text-zinc-700 dark:text-zinc-200 font-mono text-[11px] font-semibold transition cursor-pointer border border-zinc-300 dark:border-zinc-700 shadow-xs">
                                <svg class="w-3 h-3 mr-1 text-zinc-500 dark:text-zinc-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                    <path stroke-linecap="round" stroke-linejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" />
                                    <path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                </svg>
                                <span>Inspect ({{ count($alert->metadata ?? []) }})</span>
                            </button>
                        </td>

                        <!-- Actions -->
                        <td class="px-4 py-3 whitespace-nowrap text-right space-x-1">
                            @if($alert->status === 'new')
                                <form action="{{ route('security-defense.alerts.acknowledge', $alert) }}" method="POST" class="inline">
                                    @csrf
                                    <button type="submit" class="px-2.5 py-1 rounded-lg bg-zinc-100 hover:bg-zinc-200 dark:bg-[#202024] dark:hover:bg-[#28282c] text-zinc-700 dark:text-zinc-300 border border-zinc-300 dark:border-zinc-700 text-[11px] font-semibold transition cursor-pointer shadow-xs">
                                        Ack
                                    </button>
                                </form>
                            @endif

                            @if($alert->status !== 'resolved')
                                <form action="{{ route('security-defense.alerts.resolve', $alert) }}" method="POST" class="inline">
                                    @csrf
                                    <button type="submit" class="px-2.5 py-1 rounded-lg bg-zinc-900 hover:bg-zinc-800 dark:bg-zinc-100 dark:hover:bg-white text-white dark:text-zinc-900 text-[11px] font-bold transition cursor-pointer shadow-xs">
                                        Resolve
                                    </button>
                                </form>
                            @endif
                        </td>
                    </tr>
                @empty
                    <tr>
                        <td colspan="7" class="px-4 py-12 text-center text-zinc-500 dark:text-zinc-400 text-xs">
                            <div class="flex flex-col items-center justify-center space-y-2">
                                <div class="w-9 h-9 rounded-full bg-emerald-50 dark:bg-emerald-950/60 flex items-center justify-center text-emerald-600 dark:text-emerald-400">
                                    <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                        <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                    </svg>
                                </div>
                                <span class="font-semibold text-zinc-700 dark:text-zinc-300">Clean Telemetry Stream</span>
                                <span class="text-[11px]">No active threat anomalies detected. Inbound network traffic is secure.</span>
                            </div>
                        </td>
                    </tr>
                @endforelse
            </tbody>
        </table>
    </div>

    <!-- Pagination -->
    @if($alerts->hasPages())
        <div class="pt-3 border-t border-zinc-200 dark:border-zinc-800 flex justify-between items-center text-xs">
            {{ $alerts->links() }}
        </div>
    @endif
</section>
