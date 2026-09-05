@props([
    'audits',
])

<!-- Mutations Table Component -->
<div class="bg-white dark:bg-[#0f172a] border border-slate-200/90 dark:border-slate-800 rounded-xl overflow-hidden shadow-xs">
    <div class="px-4 py-3 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50/70 dark:bg-slate-900/60">
        <div class="flex items-center space-x-2">
            <span class="w-2.5 h-2.5 rounded-full bg-indigo-500"></span>
            <h3 class="text-sm font-bold text-slate-900 dark:text-white">Database Mutation Log</h3>
        </div>
        <span class="text-xs text-slate-500 dark:text-slate-400 font-mono">
            Showing {{ $audits->firstItem() ?? 0 }}-{{ $audits->lastItem() ?? 0 }} of {{ $audits->total() }} records
        </span>
    </div>

    <div class="overflow-x-auto">
        <table class="min-w-full divide-y divide-slate-200 dark:divide-slate-800 text-left text-xs">
            <thead class="bg-slate-50 dark:bg-slate-900/80 text-slate-500 dark:text-slate-400 uppercase tracking-wider font-bold text-[10px]">
                <tr>
                    <th class="px-4 py-3">Time / Event</th>
                    <th class="px-4 py-3">Auditable Entity</th>
                    <th class="px-4 py-3">Actor / IP</th>
                    <th class="px-4 py-3">Request URL & Route</th>
                    <th class="px-4 py-3">Modified Fields</th>
                    <th class="px-4 py-3">Integrity & Tamper Status</th>
                    <th class="px-4 py-3 text-right">Actions</th>
                </tr>
            </thead>
            <tbody class="divide-y divide-slate-200 dark:divide-slate-800 font-sans">
                @forelse($audits as $audit)
                    <tr class="hover:bg-slate-50/70 dark:hover:bg-slate-800/30 transition {{ $audit->is_tampered ? 'bg-rose-50/30 dark:bg-rose-950/20' : '' }}">
                        <!-- Timestamp & Event -->
                        <td class="px-4 py-3 whitespace-nowrap">
                            <div class="font-mono text-[11px] text-slate-600 dark:text-slate-300">
                                {{ $audit->created_at->format('Y-m-d H:i:s') }}
                            </div>
                            @php
                                $eventColor = match($audit->event) {
                                    'created' => 'emerald',
                                    'updated' => 'sky',
                                    'deleted' => 'rose',
                                    'restored' => 'purple',
                                    default => 'slate',
                                };
                            @endphp
                            <span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold font-mono bg-{{ $eventColor }}-50 dark:bg-{{ $eventColor }}-950 text-{{ $eventColor }}-700 dark:text-{{ $eventColor }}-300 border border-{{ $eventColor }}-300 dark:border-{{ $eventColor }}-800 mt-1 uppercase">
                                {{ $audit->event }}
                            </span>
                        </td>

                        <!-- Auditable Entity -->
                        <td class="px-4 py-3">
                            <div class="font-bold text-slate-900 dark:text-white truncate max-w-xs" title="{{ $audit->auditable_type }}">
                                {{ class_basename($audit->auditable_type) }}
                            </div>
                            <div class="font-mono text-[11px] text-slate-500 dark:text-slate-400">
                                ID: #{{ $audit->auditable_id }}
                            </div>
                        </td>

                        <!-- Actor / IP -->
                        <td class="px-4 py-3">
                            @if($audit->actor_id)
                                <div class="font-medium text-slate-900 dark:text-white flex items-center space-x-1">
                                    <span>User #{{ $audit->actor_id }}</span>
                                </div>
                                <div class="text-[10px] text-slate-500 font-mono">{{ class_basename($audit->actor_type ?? 'User') }}</div>
                            @else
                                <span class="text-slate-400 dark:text-slate-500 italic text-[11px]">System / CLI / Guest</span>
                            @endif
                            <div class="font-mono text-[10px] text-slate-500 dark:text-slate-400 mt-0.5">
                                {{ $audit->ip_address }}
                            </div>
                        </td>

                        <!-- Request URL & Method -->
                        <td class="px-4 py-3 max-w-xs truncate">
                            <div class="flex items-center space-x-1">
                                <span class="font-mono text-[10px] font-bold px-1 rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                                    {{ $audit->request_method }}
                                </span>
                                <span class="font-mono text-[11px] text-slate-700 dark:text-slate-300 truncate" title="{{ $audit->request_url }}">
                                    {{ Str::limit($audit->request_url, 40) }}
                                </span>
                            </div>
                            @if($audit->request_route)
                                <div class="font-mono text-[10px] text-slate-400 dark:text-slate-500 truncate mt-0.5">
                                    Route: {{ $audit->request_route }}
                                </div>
                            @endif
                        </td>

                        <!-- Modified Fields -->
                        <td class="px-4 py-3">
                            @if(!empty($audit->modified_fields))
                                <div class="flex flex-wrap gap-1 max-w-xs">
                                    @foreach(array_slice($audit->modified_fields, 0, 4) as $field)
                                        <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                                            {{ $field }}
                                        </span>
                                    @endforeach
                                    @if(count($audit->modified_fields) > 4)
                                        <span class="text-[10px] text-slate-400 self-center font-mono">+{{ count($audit->modified_fields) - 4 }} more</span>
                                    @endif
                                </div>
                            @else
                                <span class="text-slate-400 dark:text-slate-500 text-[11px]">&mdash;</span>
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
                                    class="px-2.5 py-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-semibold transition cursor-pointer shadow-xs">
                                View Diff
                            </button>
                            <button type="button" onclick="inspectPayload('{{ e(json_encode($audit, JSON_HEX_APOS | JSON_HEX_QUOT)) }}')"
                                    class="px-2.5 py-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-semibold transition cursor-pointer shadow-xs">
                                Payload
                            </button>
                        </td>
                    </tr>
                @empty
                    <tr>
                        <td colspan="7" class="px-4 py-12 text-center text-slate-500 dark:text-slate-400">
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
        <div class="px-4 py-3 border-t border-slate-200 dark:border-slate-800">
            {{ $audits->links() }}
        </div>
    @endif
</div>
