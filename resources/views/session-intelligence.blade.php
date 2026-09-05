@extends('security-defense::layouts.app')

@section('title', 'Session Intelligence & Client Defense')

@section('content')
    <!-- Alerts & Diagnostic Feedback -->
    @include('security-defense::components.alert-banner')

    <!-- Metric KPI Cards Row -->
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        @include('security-defense::components.stat-card', [
            'title' => 'Session Threats',
            'value' => number_format($stats['total_session_threats']),
            'subtitle' => 'Client & Post-Auth SIEM',
            'badge' => 'Sessions',
            'badgeColor' => 'zinc',
        ])

        @include('security-defense::components.stat-card', [
            'title' => 'Hijack Suspicions',
            'value' => number_format($stats['hijacks_detected']),
            'subtitle' => $stats['hijacks_detected'] > 0 ? 'Cookie theft / Subnet drift' : 'Zero hijacks detected',
            'badge' => 'Zero-Trust',
            'badgeColor' => $stats['hijacks_detected'] > 0 ? 'rose' : 'emerald',
        ])

        @include('security-defense::components.stat-card', [
            'title' => 'Velocity Anomalies',
            'value' => number_format($stats['velocity_spikes']),
            'subtitle' => 'Post-login scraping bots',
            'badge' => 'Behavioral',
            'badgeColor' => $stats['velocity_spikes'] > 0 ? 'orange' : 'zinc',
        ])

        @include('security-defense::components.stat-card', [
            'title' => 'Header Anomalies',
            'value' => number_format($stats['header_anomalies']),
            'subtitle' => 'Contradictory client UA/headers',
            'badge' => 'Client',
            'badgeColor' => $stats['header_anomalies'] > 0 ? 'orange' : 'zinc',
        ])
    </div>

    <!-- Filter Bar -->
    <div class="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-lg p-4 shadow-xs">
        <form method="GET" action="{{ route('security-defense.sessions') }}" class="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <!-- Threat Type -->
            <div>
                <label class="block text-[11px] font-medium text-zinc-500 dark:text-zinc-400 mb-1">Threat Classification</label>
                <select name="threat_type" class="w-full px-3 py-1.5 text-xs rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100 focus:ring-1 focus:ring-zinc-900 dark:focus:ring-zinc-100 focus:outline-hidden">
                    <option value="">All Session Vectors</option>
                    <option value="session_hijack_suspected" {{ ($filters['threat_type'] ?? '') === 'session_hijack_suspected' ? 'selected' : '' }}>Cookie Theft / Session Hijack</option>
                    <option value="suspicious_velocity_scraping" {{ ($filters['threat_type'] ?? '') === 'suspicious_velocity_scraping' ? 'selected' : '' }}>Post-Auth Scraping Velocity</option>
                    <option value="header_inconsistency_bot" {{ ($filters['threat_type'] ?? '') === 'header_inconsistency_bot' ? 'selected' : '' }}>Header Contradiction / Bot</option>
                    <option value="impossible_travel" {{ ($filters['threat_type'] ?? '') === 'impossible_travel' ? 'selected' : '' }}>Impossible Travel</option>
                </select>
            </div>

            <!-- Severity -->
            <div>
                <label class="block text-[11px] font-medium text-zinc-500 dark:text-zinc-400 mb-1">Severity Level</label>
                <select name="severity" class="w-full px-3 py-1.5 text-xs rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100 focus:ring-1 focus:ring-zinc-900 dark:focus:ring-zinc-100 focus:outline-hidden">
                    <option value="">All Severities</option>
                    <option value="critical" {{ ($filters['severity'] ?? '') === 'critical' ? 'selected' : '' }}>Critical</option>
                    <option value="high" {{ ($filters['severity'] ?? '') === 'high' ? 'selected' : '' }}>High</option>
                    <option value="medium" {{ ($filters['severity'] ?? '') === 'medium' ? 'selected' : '' }}>Medium</option>
                    <option value="low" {{ ($filters['severity'] ?? '') === 'low' ? 'selected' : '' }}>Low</option>
                </select>
            </div>

            <!-- Actions -->
            <div class="flex items-end space-x-2">
                <button type="submit" class="flex-1 px-3 py-1.5 bg-zinc-900 dark:bg-zinc-100 hover:bg-zinc-800 dark:hover:bg-white text-white dark:text-zinc-900 rounded-md text-xs font-semibold transition cursor-pointer">
                    Filter
                </button>
                <a href="{{ route('security-defense.sessions') }}" class="px-3 py-1.5 border border-zinc-300 dark:border-zinc-700 hover:bg-zinc-100 dark:hover:bg-zinc-800 text-zinc-700 dark:text-zinc-300 rounded-md text-xs transition cursor-pointer">
                    Reset
                </a>
            </div>
        </form>
    </div>

    <!-- Threats Table -->
    <div class="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-lg overflow-hidden shadow-xs">
        <div class="px-4 py-3 border-b border-zinc-200 dark:border-zinc-800 flex items-center justify-between">
            <div class="flex items-center space-x-2">
                <span class="w-2.5 h-2.5 rounded-full bg-orange-500"></span>
                <h3 class="text-sm font-semibold text-zinc-900 dark:text-white">Session Intelligence Telemetry</h3>
            </div>
            <span class="text-xs text-zinc-500 dark:text-zinc-400 font-mono">
                Showing {{ $alerts->firstItem() ?? 0 }}-{{ $alerts->lastItem() ?? 0 }} of {{ $alerts->total() }} alerts
            </span>
        </div>

        <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-zinc-200 dark:divide-zinc-800 text-left text-xs">
                <thead class="bg-zinc-50 dark:bg-zinc-950 text-zinc-500 dark:text-zinc-400 uppercase tracking-wider font-semibold">
                    <tr>
                        <th class="px-4 py-2.5">Severity</th>
                        <th class="px-4 py-2.5">Threat Type</th>
                        <th class="px-4 py-2.5">Entity / Target</th>
                        <th class="px-4 py-2.5">Evidence & Telemetry</th>
                        <th class="px-4 py-2.5">Status</th>
                        <th class="px-4 py-2.5 text-right">Actions</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-zinc-200 dark:divide-zinc-800 font-sans">
                    @forelse($alerts as $alert)
                        <tr class="hover:bg-zinc-50/50 dark:hover:bg-zinc-800/30 transition">
                            <!-- Severity -->
                            <td class="px-4 py-3 whitespace-nowrap">
                                @php
                                    $sevColor = match($alert->severity) {
                                        'critical' => 'rose',
                                        'high' => 'orange',
                                        'medium' => 'amber',
                                        default => 'zinc',
                                    };
                                @endphp
                                <span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold font-mono uppercase bg-{{ $sevColor }}-100 dark:bg-{{ $sevColor }}-950 text-{{ $sevColor }}-800 dark:text-{{ $sevColor }}-300 border border-{{ $sevColor }}-300 dark:border-{{ $sevColor }}-800">
                                    {{ $alert->severity }}
                                </span>
                            </td>

                            <!-- Threat Type -->
                            <td class="px-4 py-3">
                                <div class="font-bold text-zinc-900 dark:text-white font-mono text-[11px]">
                                    {{ $alert->threat_type }}
                                </div>
                                <div class="text-[10px] text-zinc-400 font-mono">Rule: {{ $alert->rule_identifier ?? 'siem_engine' }}</div>
                            </td>

                            <!-- Target -->
                            <td class="px-4 py-3">
                                <div class="font-medium text-zinc-900 dark:text-white">
                                    {{ $alert->metadata['identifier'] ?? $alert->metadata['target'] ?? $alert->metadata['ip'] ?? 'N/A' }}
                                </div>
                                <div class="text-[10px] text-zinc-500 font-mono">{{ $alert->created_at->diffForHumans() }}</div>
                            </td>

                            <!-- Evidence -->
                            <td class="px-4 py-3 max-w-sm">
                                <div class="text-[11px] text-zinc-700 dark:text-zinc-300">
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
                                <span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold font-mono uppercase bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300">
                                    {{ $alert->status }}
                                </span>
                            </td>

                            <!-- Actions -->
                            <td class="px-4 py-3 text-right space-x-1 whitespace-nowrap">
                                @if($alert->status === 'new')
                                    <form method="POST" action="{{ route('security-defense.alerts.acknowledge', $alert) }}" class="inline">
                                        @csrf
                                        <button type="submit" class="px-2 py-1 rounded text-[11px] font-medium bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300 border border-amber-300 dark:border-amber-800 hover:bg-amber-100 dark:hover:bg-amber-900/60 transition cursor-pointer">
                                            Ack
                                        </button>
                                    </form>
                                @endif

                                @if($alert->status !== 'resolved')
                                    <form method="POST" action="{{ route('security-defense.alerts.resolve', $alert) }}" class="inline">
                                        @csrf
                                        <button type="submit" class="px-2 py-1 rounded text-[11px] font-medium bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800 hover:bg-emerald-100 dark:hover:bg-emerald-900/60 transition cursor-pointer">
                                            Resolve
                                        </button>
                                    </form>
                                @endif
                            </td>
                        </tr>
                    @empty
                        <tr>
                            <td colspan="6" class="px-4 py-8 text-center text-zinc-500 dark:text-zinc-400">
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
            <div class="px-4 py-3 border-t border-zinc-200 dark:border-zinc-800">
                {{ $alerts->links() }}
            </div>
        @endif
    </div>
@endsection
