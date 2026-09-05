@extends('security-defense::layouts.app')

@section('title', 'Database Mutation & Tamper Monitoring')

@section('content')
    <!-- Alerts & Diagnostic Feedback -->
    @include('security-defense::components.alert-banner')

    <!-- Metric KPI Cards Row -->
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        @include('security-defense::components.stat-card', [
            'title' => 'Total Mutations',
            'value' => number_format($stats['total']),
            'subtitle' => 'Recorded in Audit Trail',
            'badge' => 'Database',
            'badgeColor' => 'zinc',
        ])

        @include('security-defense::components.stat-card', [
            'title' => 'Tamper Detected',
            'value' => number_format($stats['tampered']),
            'subtitle' => $stats['tampered'] > 0 ? 'Burp Suite / Mass Assignment' : 'Zero tampering detected',
            'badge' => 'Integrity',
            'badgeColor' => $stats['tampered'] > 0 ? 'rose' : 'emerald',
        ])

        @include('security-defense::components.stat-card', [
            'title' => 'Today\'s Mutations',
            'value' => number_format($stats['today']),
            'subtitle' => 'Captured in last 24h',
            'badge' => 'Live',
            'badgeColor' => 'blue',
        ])

        @include('security-defense::components.stat-card', [
            'title' => 'Distinct Actors',
            'value' => number_format($stats['unique_actors']),
            'subtitle' => 'Authenticated Users / Admins',
            'badge' => 'Actors',
            'badgeColor' => 'zinc',
        ])
    </div>

    <!-- Filter Bar -->
    <div class="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-lg p-4 shadow-xs">
        <form method="GET" action="{{ route('security-defense.data-audits') }}" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
            <!-- Search -->
            <div>
                <label class="block text-[11px] font-medium text-zinc-500 dark:text-zinc-400 mb-1">Search Identifier / URL / IP</label>
                <input type="text" name="search" value="{{ $filters['search'] ?? '' }}" placeholder="e.g. 192.168.1.1, /admin/users..."
                       class="w-full px-3 py-1.5 text-xs rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100 focus:ring-1 focus:ring-zinc-900 dark:focus:ring-zinc-100 focus:outline-hidden">
            </div>

            <!-- Event -->
            <div>
                <label class="block text-[11px] font-medium text-zinc-500 dark:text-zinc-400 mb-1">Mutation Event</label>
                <select name="event" class="w-full px-3 py-1.5 text-xs rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100 focus:ring-1 focus:ring-zinc-900 dark:focus:ring-zinc-100 focus:outline-hidden">
                    <option value="">All Events</option>
                    <option value="created" {{ ($filters['event'] ?? '') === 'created' ? 'selected' : '' }}>Created</option>
                    <option value="updated" {{ ($filters['event'] ?? '') === 'updated' ? 'selected' : '' }}>Updated</option>
                    <option value="deleted" {{ ($filters['event'] ?? '') === 'deleted' ? 'selected' : '' }}>Deleted</option>
                    <option value="restored" {{ ($filters['event'] ?? '') === 'restored' ? 'selected' : '' }}>Restored</option>
                </select>
            </div>

            <!-- Model -->
            <div>
                <label class="block text-[11px] font-medium text-zinc-500 dark:text-zinc-400 mb-1">Auditable Model</label>
                <input type="text" name="auditable_type" value="{{ $filters['auditable_type'] ?? '' }}" placeholder="e.g. User, Order..."
                       class="w-full px-3 py-1.5 text-xs rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100 focus:ring-1 focus:ring-zinc-900 dark:focus:ring-zinc-100 focus:outline-hidden">
            </div>

            <!-- Tampering Status -->
            <div>
                <label class="block text-[11px] font-medium text-zinc-500 dark:text-zinc-400 mb-1">Integrity Status</label>
                <select name="tampered" class="w-full px-3 py-1.5 text-xs rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100 focus:ring-1 focus:ring-zinc-900 dark:focus:ring-zinc-100 focus:outline-hidden">
                    <option value="">All Records</option>
                    <option value="1" {{ ($filters['tampered'] ?? '') === '1' ? 'selected' : '' }}>🚨 Tamper Detected Only</option>
                    <option value="0" {{ ($filters['tampered'] ?? '') === '0' ? 'selected' : '' }}>Clean Only</option>
                </select>
            </div>

            <!-- Actions -->
            <div class="flex items-end space-x-2">
                <button type="submit" class="flex-1 px-3 py-1.5 bg-zinc-900 dark:bg-zinc-100 hover:bg-zinc-800 dark:hover:bg-white text-white dark:text-zinc-900 rounded-md text-xs font-semibold transition cursor-pointer">
                    Apply Filter
                </button>
                <a href="{{ route('security-defense.data-audits') }}" class="px-3 py-1.5 border border-zinc-300 dark:border-zinc-700 hover:bg-zinc-100 dark:hover:bg-zinc-800 text-zinc-700 dark:text-zinc-300 rounded-md text-xs transition cursor-pointer">
                    Reset
                </a>
            </div>
        </form>
    </div>

    <!-- Mutations Table -->
    <div class="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-lg overflow-hidden shadow-xs">
        <div class="px-4 py-3 border-b border-zinc-200 dark:border-zinc-800 flex items-center justify-between">
            <div class="flex items-center space-x-2">
                <span class="w-2.5 h-2.5 rounded-full bg-blue-500"></span>
                <h3 class="text-sm font-semibold text-zinc-900 dark:text-white">Database Mutation Log</h3>
            </div>
            <span class="text-xs text-zinc-500 dark:text-zinc-400 font-mono">
                Showing {{ $audits->firstItem() ?? 0 }}-{{ $audits->lastItem() ?? 0 }} of {{ $audits->total() }} records
            </span>
        </div>

        <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-zinc-200 dark:divide-zinc-800 text-left text-xs">
                <thead class="bg-zinc-50 dark:bg-zinc-950 text-zinc-500 dark:text-zinc-400 uppercase tracking-wider font-semibold">
                    <tr>
                        <th class="px-4 py-2.5">Time / Event</th>
                        <th class="px-4 py-2.5">Auditable Entity</th>
                        <th class="px-4 py-2.5">Actor / IP</th>
                        <th class="px-4 py-2.5">Request URL & Route</th>
                        <th class="px-4 py-2.5">Modified Fields</th>
                        <th class="px-4 py-2.5">Integrity & Tamper Status</th>
                        <th class="px-4 py-2.5 text-right">Actions</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-zinc-200 dark:divide-zinc-800 font-sans">
                    @forelse($audits as $audit)
                        <tr class="hover:bg-zinc-50/50 dark:hover:bg-zinc-800/30 transition {{ $audit->is_tampered ? 'bg-rose-50/30 dark:bg-rose-950/20' : '' }}">
                            <!-- Timestamp & Event -->
                            <td class="px-4 py-3 whitespace-nowrap">
                                <div class="font-mono text-[11px] text-zinc-600 dark:text-zinc-300">
                                    {{ $audit->created_at->format('Y-m-d H:i:s') }}
                                </div>
                                @php
                                    $eventColor = match($audit->event) {
                                        'created' => 'emerald',
                                        'updated' => 'blue',
                                        'deleted' => 'rose',
                                        'restored' => 'purple',
                                        default => 'zinc',
                                    };
                                @endphp
                                <span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold font-mono bg-{{ $eventColor }}-50 dark:bg-{{ $eventColor }}-950 text-{{ $eventColor }}-700 dark:text-{{ $eventColor }}-300 border border-{{ $eventColor }}-300 dark:border-{{ $eventColor }}-800 mt-1 uppercase">
                                    {{ $audit->event }}
                                </span>
                            </td>

                            <!-- Auditable Entity -->
                            <td class="px-4 py-3">
                                <div class="font-medium text-zinc-900 dark:text-white truncate max-w-xs" title="{{ $audit->auditable_type }}">
                                    {{ class_basename($audit->auditable_type) }}
                                </div>
                                <div class="font-mono text-[11px] text-zinc-500 dark:text-zinc-400">
                                    ID: #{{ $audit->auditable_id }}
                                </div>
                            </td>

                            <!-- Actor / IP -->
                            <td class="px-4 py-3">
                                @if($audit->actor_id)
                                    <div class="font-medium text-zinc-900 dark:text-white flex items-center space-x-1">
                                        <span>User #{{ $audit->actor_id }}</span>
                                    </div>
                                    <div class="text-[10px] text-zinc-500 font-mono">{{ class_basename($audit->actor_type ?? 'User') }}</div>
                                @else
                                    <span class="text-zinc-400 dark:text-zinc-500 italic text-[11px]">System / CLI / Guest</span>
                                @endif
                                <div class="font-mono text-[10px] text-zinc-500 dark:text-zinc-400 mt-0.5">
                                    {{ $audit->ip_address }}
                                </div>
                            </td>

                            <!-- Request URL & Method -->
                            <td class="px-4 py-3 max-w-xs truncate">
                                <div class="flex items-center space-x-1">
                                    <span class="font-mono text-[10px] font-bold px-1 rounded bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300">
                                        {{ $audit->request_method }}
                                    </span>
                                    <span class="font-mono text-[11px] text-zinc-700 dark:text-zinc-300 truncate" title="{{ $audit->request_url }}">
                                        {{ Str::limit($audit->request_url, 40) }}
                                    </span>
                                </div>
                                @if($audit->request_route)
                                    <div class="font-mono text-[10px] text-zinc-400 dark:text-zinc-500 truncate mt-0.5">
                                        Route: {{ $audit->request_route }}
                                    </div>
                                @endif
                            </td>

                            <!-- Modified Fields -->
                            <td class="px-4 py-3">
                                @if(!empty($audit->modified_fields))
                                    <div class="flex flex-wrap gap-1 max-w-xs">
                                        @foreach(array_slice($audit->modified_fields, 0, 4) as $field)
                                            <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300 border border-zinc-200 dark:border-zinc-700">
                                                {{ $field }}
                                            </span>
                                        @endforeach
                                        @if(count($audit->modified_fields) > 4)
                                            <span class="text-[10px] text-zinc-400 self-center font-mono">+{{ count($audit->modified_fields) - 4 }} more</span>
                                        @endif
                                    </div>
                                @else
                                    <span class="text-zinc-400 dark:text-zinc-500 text-[11px]">&mdash;</span>
                                @endif
                            </td>

                            <!-- Integrity & Tamper Status -->
                            <td class="px-4 py-3">
                                @if($audit->is_tampered)
                                    <div class="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-bold bg-rose-100 dark:bg-rose-950 text-rose-800 dark:text-rose-300 border border-rose-300 dark:border-rose-700 animate-pulse" title="Burp Suite Parameter Tampering Detected">
                                        <svg class="w-3 h-3 text-rose-600 dark:text-rose-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5">
                                            <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                                        </svg>
                                        <span>BURP TAMPER DETECTED</span>
                                    </div>
                                    @if(!empty($audit->tamper_reasons))
                                        <div class="text-[10px] text-rose-600 dark:text-rose-400 mt-1 max-w-xs truncate" title="{{ implode(', ', $audit->tamper_reasons) }}">
                                            {{ $audit->tamper_reasons[0] }}
                                        </div>
                                    @endif
                                @else
                                    <span class="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-medium bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800">
                                        <span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
                                        <span>Verified Clean</span>
                                    </span>
                                @endif
                            </td>

                            <!-- Actions -->
                            <td class="px-4 py-3 text-right space-x-1 whitespace-nowrap">
                                <button type="button" onclick="inspectDiff('{{ e(json_encode($audit, JSON_HEX_APOS | JSON_HEX_QUOT)) }}')"
                                        class="px-2 py-1 rounded border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-800 hover:bg-zinc-100 dark:hover:bg-zinc-700 text-zinc-700 dark:text-zinc-200 text-xs transition cursor-pointer">
                                    View Diff
                                </button>
                                <button type="button" onclick="inspectPayload('{{ e(json_encode($audit, JSON_HEX_APOS | JSON_HEX_QUOT)) }}')"
                                        class="px-2 py-1 rounded border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-800 hover:bg-zinc-100 dark:hover:bg-zinc-700 text-zinc-700 dark:text-zinc-200 text-xs transition cursor-pointer">
                                    Payload
                                </button>
                            </td>
                        </tr>
                    @empty
                        <tr>
                            <td colspan="7" class="px-4 py-8 text-center text-zinc-500 dark:text-zinc-400">
                                <svg class="w-8 h-8 mx-auto mb-2 opacity-40" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                                </svg>
                                No database mutation logs found matching criteria.
                            </td>
                        </tr>
                    @endforelse
                </tbody>
            </table>
        </div>

        @if($audits->hasPages())
            <div class="px-4 py-3 border-t border-zinc-200 dark:border-zinc-800">
                {{ $audits->links() }}
            </div>
        @endif
    </div>

    <!-- Interactive Diff & Payload Modal -->
    <div id="audit-modal" class="fixed inset-0 z-50 hidden bg-zinc-950/70 backdrop-blur-xs flex items-center justify-center p-4">
        <div class="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-xl max-w-4xl w-full max-h-[85vh] flex flex-col shadow-2xl">
            <!-- Modal Header -->
            <div class="px-5 py-4 border-b border-zinc-200 dark:border-zinc-800 flex items-center justify-between">
                <div>
                    <h3 id="modal-title" class="text-sm font-bold text-zinc-900 dark:text-white">Mutation Details</h3>
                    <p id="modal-subtitle" class="text-xs text-zinc-500 font-mono mt-0.5"></p>
                </div>
                <button type="button" onclick="closeAuditModal()" class="p-1 rounded text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 cursor-pointer">
                    <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                    </svg>
                </button>
            </div>

            <!-- Modal Body -->
            <div id="modal-body" class="p-5 overflow-y-auto space-y-4 flex-1 text-xs">
                <!-- Content injected dynamically via JS -->
            </div>

            <!-- Modal Footer -->
            <div class="px-5 py-3 border-t border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 flex justify-end">
                <button type="button" onclick="closeAuditModal()" class="px-3 py-1.5 rounded-md bg-zinc-200 dark:bg-zinc-800 text-zinc-800 dark:text-zinc-200 text-xs font-semibold cursor-pointer hover:bg-zinc-300 dark:hover:bg-zinc-700 transition">
                    Close
                </button>
            </div>
        </div>
    </div>
@endsection

@push('scripts')
<script>
    function parseAudit(auditData) {
        if (typeof auditData === 'object' && auditData !== null) {
            return auditData;
        }
        try {
            return JSON.parse(auditData);
        } catch (e) {
            console.error('Failed to parse audit payload', e);
            return {};
        }
    }

    function inspectDiff(rawAudit) {
        const audit = parseAudit(rawAudit);
        document.getElementById('modal-title').innerText = 'Side-by-Side Attribute Diff • ' + ((audit.auditable_type || '').split('\\').pop()) + ' #' + (audit.auditable_id || '');
        document.getElementById('modal-subtitle').innerText = 'Event: ' + (audit.event ? audit.event.toUpperCase() : '') + ' | Actor: ' + (audit.actor_id ? 'User #' + audit.actor_id : 'System') + ' | ' + (audit.created_at || '');

        const body = document.getElementById('modal-body');
        let html = '';

        if (audit.is_tampered) {
            html += `
                <div class="p-3 rounded-lg bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 text-rose-900 dark:text-rose-200">
                    <div class="font-bold flex items-center space-x-1 text-xs">
                        <span>⚠️ Burp Suite Parameter Tampering Detected</span>
                    </div>
                    <ul class="list-disc list-inside mt-1 text-[11px] space-y-0.5">
                        ${(audit.tamper_reasons || []).map(r => `<li>${escapeHtml(r)}</li>`).join('')}
                    </ul>
                </div>
            `;
        }

        const oldVals = audit.old_values || {};
        const newVals = audit.new_values || {};
        const fields = audit.modified_fields || Object.keys(Object.assign({}, oldVals, newVals));

        html += `
            <div class="border border-zinc-200 dark:border-zinc-800 rounded-lg overflow-hidden">
                <table class="min-w-full divide-y divide-zinc-200 dark:divide-zinc-800 text-left font-mono text-[11px]">
                    <thead class="bg-zinc-100 dark:bg-zinc-800/80 font-bold text-zinc-600 dark:text-zinc-300">
                        <tr>
                            <th class="px-3 py-2 w-1/4">Field</th>
                            <th class="px-3 py-2 w-3/8 text-rose-600 dark:text-rose-400">Previous Value (Old)</th>
                            <th class="px-3 py-2 w-3/8 text-emerald-600 dark:text-emerald-400">Updated Value (New)</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-zinc-200 dark:divide-zinc-800">
        `;

        if (fields.length === 0) {
            html += `<tr><td colspan="3" class="p-4 text-center text-zinc-400">No field changes captured.</td></tr>`;
        } else {
            fields.forEach(f => {
                const oldVal = oldVals[f] !== undefined ? JSON.stringify(oldVals[f]) : '<span class="text-zinc-400 italic">null</span>';
                const newVal = newVals[f] !== undefined ? JSON.stringify(newVals[f]) : '<span class="text-zinc-400 italic">null</span>';
                html += `
                    <tr class="hover:bg-zinc-50 dark:hover:bg-zinc-800/30">
                        <td class="px-3 py-2 font-bold text-zinc-800 dark:text-zinc-200">${escapeHtml(f)}</td>
                        <td class="px-3 py-2 text-rose-700 dark:text-rose-300 bg-rose-50/20 dark:bg-rose-950/10 break-all">${oldVal}</td>
                        <td class="px-3 py-2 text-emerald-700 dark:text-emerald-300 bg-emerald-50/20 dark:bg-emerald-950/10 break-all">${newVal}</td>
                    </tr>
                `;
            });
        }

        html += `</tbody></table></div>`;
        body.innerHTML = html;
        document.getElementById('audit-modal').classList.remove('hidden');
    }

    function inspectPayload(rawAudit) {
        const audit = parseAudit(rawAudit);
        document.getElementById('modal-title').innerText = 'Request Payload Snapshot • ' + (audit.request_method || '') + ' ' + (audit.request_url || '');
        document.getElementById('modal-subtitle').innerText = 'IP: ' + (audit.ip_address || '') + ' | Route: ' + (audit.request_route || 'N/A');

        const body = document.getElementById('modal-body');
        let html = `
            <div class="space-y-3 font-mono">
                <div class="grid grid-cols-2 gap-2 text-[11px] p-3 bg-zinc-50 dark:bg-zinc-800/50 rounded-lg border border-zinc-200 dark:border-zinc-800">
                    <div><span class="text-zinc-500">Method:</span> <strong class="text-zinc-900 dark:text-white">${escapeHtml(audit.request_method)}</strong></div>
                    <div><span class="text-zinc-500">IP Address:</span> <strong class="text-zinc-900 dark:text-white">${escapeHtml(audit.ip_address)}</strong></div>
                    <div class="col-span-2"><span class="text-zinc-500">URL:</span> <strong class="text-zinc-900 dark:text-white">${escapeHtml(audit.request_url)}</strong></div>
                    <div class="col-span-2"><span class="text-zinc-500">User Agent:</span> <span class="text-zinc-700 dark:text-zinc-300">${escapeHtml(audit.user_agent || 'N/A')}</span></div>
                </div>

                <div>
                    <h4 class="text-xs font-bold text-zinc-700 dark:text-zinc-300 mb-1">Sanitized HTTP Request Payload:</h4>
                    <pre class="p-3 rounded-lg bg-zinc-950 text-emerald-400 text-[11px] overflow-x-auto border border-zinc-800 max-h-96"><code>${escapeHtml(JSON.stringify(audit.payload_snapshot || {}, null, 2))}</code></pre>
                </div>
            </div>
        `;

        body.innerHTML = html;
        document.getElementById('audit-modal').classList.remove('hidden');
    }

    function closeAuditModal() {
        document.getElementById('audit-modal').classList.add('hidden');
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }
</script>
@endpush
