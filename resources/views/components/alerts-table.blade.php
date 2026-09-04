@props([
    'alerts',
    'filters' => [],
])

<section class="rounded-lg bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 p-5 space-y-4">
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
            <h2 class="text-sm font-bold text-zinc-900 dark:text-white tracking-tight flex items-center space-x-2">
                <span>Security Alerts & Incident Logs</span>
            </h2>
            <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">Real-time correlated telemetry records and triage queue.</p>
        </div>

        <!-- Filters Form -->
        <form method="GET" class="flex flex-wrap items-center gap-2">
            <select name="status" onchange="this.form.submit()" class="bg-zinc-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 text-zinc-700 dark:text-zinc-300 text-xs rounded-md px-2.5 py-1.5 focus:ring-1 focus:ring-zinc-400 focus:outline-none">
                <option value="">All Statuses</option>
                <option value="new" {{ request('status') === 'new' ? 'selected' : '' }}>New</option>
                <option value="acknowledged" {{ request('status') === 'acknowledged' ? 'selected' : '' }}>Acknowledged</option>
                <option value="resolved" {{ request('status') === 'resolved' ? 'selected' : '' }}>Resolved</option>
            </select>

            <select name="severity" onchange="this.form.submit()" class="bg-zinc-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 text-zinc-700 dark:text-zinc-300 text-xs rounded-md px-2.5 py-1.5 focus:ring-1 focus:ring-zinc-400 focus:outline-none">
                <option value="">All Severities</option>
                <option value="critical" {{ request('severity') === 'critical' ? 'selected' : '' }}>Critical</option>
                <option value="high" {{ request('severity') === 'high' ? 'selected' : '' }}>High</option>
                <option value="medium" {{ request('severity') === 'medium' ? 'selected' : '' }}>Medium</option>
                <option value="low" {{ request('severity') === 'low' ? 'selected' : '' }}>Low</option>
            </select>

            @if(request()->hasAny(['status', 'severity', 'threat_type']))
                <a href="{{ route('security-defense.dashboard') }}" class="text-xs text-zinc-500 hover:text-zinc-900 dark:hover:text-white px-2 py-1 transition">Reset</a>
            @endif
        </form>
    </div>

    <!-- Table -->
    <div class="overflow-x-auto rounded-md border border-zinc-200 dark:border-zinc-800">
        <table class="min-w-full divide-y divide-zinc-200 dark:divide-zinc-800 text-left text-xs">
            <thead class="bg-zinc-50 dark:bg-zinc-950 font-semibold text-zinc-600 dark:text-zinc-400 uppercase tracking-wider text-[10px]">
                <tr>
                    <th class="px-3.5 py-2.5">Severity</th>
                    <th class="px-3.5 py-2.5">Threat Type</th>
                    <th class="px-3.5 py-2.5">Fingerprint</th>
                    <th class="px-3.5 py-2.5">Detected</th>
                    <th class="px-3.5 py-2.5">Status</th>
                    <th class="px-3.5 py-2.5">Telemetry</th>
                    <th class="px-3.5 py-2.5 text-right">Actions</th>
                </tr>
            </thead>
            <tbody class="divide-y divide-zinc-200 dark:divide-zinc-800/80 bg-white dark:bg-zinc-900/60">
                @forelse($alerts as $alert)
                    @php
                        $sev = strtolower($alert->severity);
                        $sevBadge = match($sev) {
                            'critical' => 'bg-rose-50 text-rose-700 border-rose-200 dark:bg-rose-950/60 dark:text-rose-400 dark:border-rose-800',
                            'high' => 'bg-orange-50 text-orange-700 border-orange-200 dark:bg-orange-950/60 dark:text-orange-400 dark:border-orange-800',
                            'medium' => 'bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950/60 dark:text-amber-400 dark:border-amber-800',
                            default => 'bg-zinc-100 text-zinc-700 border-zinc-200 dark:bg-zinc-800 dark:text-zinc-300 dark:border-zinc-700',
                        };
                        $sevDot = match($sev) {
                            'critical' => 'bg-rose-500',
                            'high' => 'bg-orange-500',
                            'medium' => 'bg-amber-500',
                            default => 'bg-zinc-400',
                        };
                    @endphp
                    <tr class="hover:bg-zinc-50 dark:hover:bg-zinc-800/40 transition">
                        <!-- Severity -->
                        <td class="px-3.5 py-2.5 whitespace-nowrap">
                            <span class="inline-flex items-center space-x-1.5 px-1.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border {{ $sevBadge }}">
                                <span class="w-1.5 h-1.5 rounded-full {{ $sevDot }}" aria-hidden="true"></span>
                                <span>{{ $alert->severity }}</span>
                            </span>
                        </td>

                        <!-- Threat Type -->
                        <td class="px-3.5 py-2.5">
                            <div class="font-semibold text-zinc-800 dark:text-zinc-200 capitalize text-xs">
                                {{ str_replace('_', ' ', $alert->threat_type) }}
                            </div>
                            <div class="text-[10px] text-zinc-400 dark:text-zinc-500 font-mono">
                                {{ $alert->rule_identifier ?? 'custom' }}
                            </div>
                        </td>

                        <!-- Fingerprint -->
                        <td class="px-3.5 py-2.5 whitespace-nowrap">
                            <code class="px-1.5 py-0.5 rounded bg-zinc-100 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 text-[10px] text-zinc-700 dark:text-zinc-300 font-mono">
                                {{ substr($alert->fingerprint, 0, 12) }}...
                            </code>
                        </td>

                        <!-- Detected At -->
                        <td class="px-3.5 py-2.5 whitespace-nowrap text-zinc-500 dark:text-zinc-400 text-[11px]">
                            {{ $alert->created_at ? $alert->created_at->diffForHumans() : 'Just now' }}
                        </td>

                        <!-- Status -->
                        <td class="px-3.5 py-2.5 whitespace-nowrap">
                            @if($alert->status === 'new')
                                <span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold bg-rose-50 text-rose-700 border border-rose-200 dark:bg-rose-950/40 dark:text-rose-400 dark:border-rose-900">NEW</span>
                            @elseif($alert->status === 'acknowledged')
                                <span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold bg-amber-50 text-amber-700 border border-amber-200 dark:bg-amber-950/40 dark:text-amber-400 dark:border-amber-900">ACK</span>
                            @else
                                <span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-400 dark:border-emerald-900">RESOLVED</span>
                            @endif
                        </td>

                        <!-- Telemetry Inspect -->
                        <td class="px-3.5 py-2.5 whitespace-nowrap">
                            <button type="button" onclick="showMetadataModal({{ $alert->id }}, '{{ e(json_encode($alert->metadata ?? [], JSON_HEX_APOS | JSON_HEX_QUOT)) }}')" class="px-2 py-1 rounded bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-800 dark:hover:bg-zinc-700 text-zinc-700 dark:text-zinc-300 font-mono text-[10px] transition cursor-pointer border border-zinc-200 dark:border-zinc-700">
                                Inspect ({{ count($alert->metadata ?? []) }})
                            </button>
                        </td>

                        <!-- Actions -->
                        <td class="px-3.5 py-2.5 whitespace-nowrap text-right space-x-1">
                            @if($alert->status === 'new')
                                <form action="{{ route('security-defense.alerts.acknowledge', $alert) }}" method="POST" class="inline">
                                    @csrf
                                    <button type="submit" class="px-2 py-0.5 rounded bg-zinc-100 hover:bg-zinc-200 dark:bg-zinc-800 dark:hover:bg-zinc-700 text-zinc-700 dark:text-zinc-300 border border-zinc-300 dark:border-zinc-700 text-[10px] font-medium transition cursor-pointer">
                                        Ack
                                    </button>
                                </form>
                            @endif

                            @if($alert->status !== 'resolved')
                                <form action="{{ route('security-defense.alerts.resolve', $alert) }}" method="POST" class="inline">
                                    @csrf
                                    <button type="submit" class="px-2 py-0.5 rounded bg-zinc-900 hover:bg-zinc-800 dark:bg-zinc-100 dark:hover:bg-white text-white dark:text-zinc-900 text-[10px] font-semibold transition cursor-pointer">
                                        Resolve
                                    </button>
                                </form>
                            @endif
                        </td>
                    </tr>
                @empty
                    <tr>
                        <td colspan="7" class="px-4 py-8 text-center text-zinc-500 dark:text-zinc-400 text-xs">
                            No security defense alerts recorded. Telemetry stream is clean.
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
