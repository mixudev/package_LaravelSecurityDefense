@props([
    'alerts',
])

<!-- Threats Table Component -->
<div class="bg-white dark:bg-[#0f172a] border border-slate-200/90 dark:border-slate-800 rounded-xl overflow-hidden shadow-xs">
    <div class="px-4 py-3 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50/70 dark:bg-slate-900/60">
        <div class="flex items-center space-x-2">
            <span class="w-2.5 h-2.5 rounded-full bg-orange-500"></span>
            <h3 class="text-sm font-bold text-slate-900 dark:text-white">Session Intelligence Telemetry</h3>
        </div>
        <span class="text-xs text-slate-500 dark:text-slate-400 font-mono">
            Showing {{ $alerts->firstItem() ?? 0 }}-{{ $alerts->lastItem() ?? 0 }} of {{ $alerts->total() }} alerts
        </span>
    </div>

    <div class="overflow-x-auto">
        <table class="min-w-full divide-y divide-slate-200 dark:divide-slate-800 text-left text-xs">
            <thead class="bg-slate-50 dark:bg-slate-900/80 text-slate-500 dark:text-slate-400 uppercase tracking-wider font-bold text-[10px]">
                <tr>
                    <th class="px-4 py-3">Severity</th>
                    <th class="px-4 py-3">Threat Type</th>
                    <th class="px-4 py-3">Entity / Target</th>
                    <th class="px-4 py-3">Evidence & Telemetry</th>
                    <th class="px-4 py-3">Status</th>
                    <th class="px-4 py-3 text-right">Actions</th>
                </tr>
            </thead>
            <tbody class="divide-y divide-slate-200 dark:divide-slate-800 font-sans">
                @forelse($alerts as $alert)
                    <tr class="hover:bg-slate-50/70 dark:hover:bg-slate-800/30 transition">
                        <!-- Severity -->
                        <td class="px-4 py-3 whitespace-nowrap">
                            @php
                                $sevColor = match($alert->severity) {
                                    'critical' => 'rose',
                                    'high' => 'orange',
                                    'medium' => 'amber',
                                    default => 'slate',
                                };
                            @endphp
                            <span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold font-mono uppercase bg-{{ $sevColor }}-100 dark:bg-{{ $sevColor }}-950 text-{{ $sevColor }}-800 dark:text-{{ $sevColor }}-300 border border-{{ $sevColor }}-300 dark:border-{{ $sevColor }}-800">
                                {{ $alert->severity }}
                            </span>
                        </td>

                        <!-- Threat Type -->
                        <td class="px-4 py-3">
                            <div class="font-bold text-slate-900 dark:text-white font-mono text-[11px]">
                                {{ $alert->threat_type }}
                            </div>
                            <div class="text-[10px] text-slate-500 dark:text-slate-400 font-mono">Rule: {{ $alert->rule_identifier ?? 'siem_engine' }}</div>
                        </td>

                        <!-- Target -->
                        <td class="px-4 py-3">
                            <div class="font-medium text-slate-900 dark:text-white">
                                {{ $alert->metadata['identifier'] ?? $alert->metadata['target'] ?? $alert->metadata['ip'] ?? 'N/A' }}
                            </div>
                            <div class="text-[10px] text-slate-500 dark:text-slate-400 font-mono">{{ $alert->created_at->diffForHumans() }}</div>
                        </td>

                        <!-- Evidence -->
                        <td class="px-4 py-3 max-w-sm">
                            <div class="text-[11px] text-slate-700 dark:text-slate-300">
                                {{ $alert->metadata['reason'] ?? $alert->metadata['reasons'] ?? 'Anomalous session behavior detected' }}
                            </div>
                            @if(!empty($alert->metadata['mismatches']))
                                <div class="mt-1 flex gap-1">
                                    @foreach((array)$alert->metadata['mismatches'] as $mismatch)
                                        <span class="px-1.5 py-0.5 rounded text-[9px] font-mono bg-rose-100 dark:bg-rose-950 text-rose-700 dark:text-rose-300 border border-rose-200 dark:border-rose-800">
                                            {{ $mismatch }}
                                        </span>
                                    @endforeach
                                </div>
                            @endif
                        </td>

                        <!-- Status -->
                        <td class="px-4 py-3 whitespace-nowrap">
                            <span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold font-mono uppercase bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                                {{ $alert->status }}
                            </span>
                        </td>

                        <!-- Actions -->
                        <td class="px-4 py-3 text-right space-x-1 whitespace-nowrap">
                            @if($alert->status === 'new')
                                <form method="POST" action="{{ route('security-defense.alerts.acknowledge', $alert) }}" class="inline">
                                    @csrf
                                    <button type="submit" class="px-2.5 py-1 rounded-lg text-[11px] font-medium bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300 border border-amber-300 dark:border-amber-800 hover:bg-amber-100 dark:hover:bg-amber-900/60 transition cursor-pointer shadow-xs">
                                        Ack
                                    </button>
                                </form>
                            @endif

                            @if($alert->status !== 'resolved')
                                <form method="POST" action="{{ route('security-defense.alerts.resolve', $alert) }}" class="inline">
                                    @csrf
                                    <button type="submit" class="px-2.5 py-1 rounded-lg text-[11px] font-medium bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800 hover:bg-emerald-100 dark:hover:bg-emerald-900/60 transition cursor-pointer shadow-xs">
                                        Resolve
                                    </button>
                                </form>
                            @endif
                        </td>
                    </tr>
                @empty
                    <tr>
                        <td colspan="6" class="px-4 py-12 text-center text-slate-500 dark:text-slate-400">
                            <svg class="w-8 h-8 mx-auto mb-2 opacity-40" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                            </svg>
                            No session intelligence threat alerts recorded.
                        </td>
                    </tr>
                @endforelse
            </tbody>
        </table>
    </div>

    @if($alerts->hasPages())
        <div class="px-4 py-3 border-t border-slate-200 dark:border-slate-800">
            {{ $alerts->links() }}
        </div>
    @endif
</div>
