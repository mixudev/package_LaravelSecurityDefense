<!-- Interactive Diff & Payload Modal Component -->
<div id="audit-modal" class="fixed inset-0 z-50 hidden bg-slate-950/70 backdrop-blur-xs flex items-center justify-center p-4">
    <div class="bg-white dark:bg-[#0f172a] border border-slate-200 dark:border-slate-800 rounded-2xl max-w-4xl w-full max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
        <!-- Modal Header -->
        <div class="px-5 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50/70 dark:bg-slate-900/60">
            <div>
                <h3 id="modal-title" class="text-sm font-bold text-slate-900 dark:text-white">Mutation Details</h3>
                <p id="modal-subtitle" class="text-xs text-slate-500 dark:text-slate-400 font-mono mt-0.5"></p>
            </div>
            <button type="button" onclick="closeAuditModal()" class="w-8 h-8 rounded-lg flex items-center justify-center text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer text-lg font-bold">
                &times;
            </button>
        </div>

        <!-- Modal Body -->
        <div id="modal-body" class="p-5 overflow-y-auto space-y-4 flex-1 text-xs">
            <!-- Content injected dynamically via JS -->
        </div>

        <!-- Modal Footer -->
        <div class="px-5 py-3 border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 flex justify-end">
            <button type="button" onclick="closeAuditModal()" class="px-4 py-1.5 rounded-lg bg-slate-200 hover:bg-slate-300 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 text-xs font-semibold cursor-pointer transition">
                Close
            </button>
        </div>
    </div>
</div>

<script>
    function parseAudit(auditData) {
        if (typeof auditData === 'object' && auditData !== null) return auditData;
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
                <div class="p-3 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 text-rose-900 dark:text-rose-200">
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
            <div class="border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden">
                <table class="min-w-full divide-y divide-slate-200 dark:divide-slate-800 text-left font-mono text-[11px]">
                    <thead class="bg-slate-100 dark:bg-slate-800/80 font-bold text-slate-600 dark:text-slate-300">
                        <tr>
                            <th class="px-3 py-2 w-1/4">Field</th>
                            <th class="px-3 py-2 w-3/8 text-rose-600 dark:text-rose-400">Previous Value (Old)</th>
                            <th class="px-3 py-2 w-3/8 text-emerald-600 dark:text-emerald-400">Updated Value (New)</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-200 dark:divide-slate-800">
        `;

        if (fields.length === 0) {
            html += `<tr><td colspan="3" class="p-4 text-center text-slate-400">No field changes captured.</td></tr>`;
        } else {
            fields.forEach(f => {
                const oldVal = oldVals[f] !== undefined ? JSON.stringify(oldVals[f]) : '<span class="text-slate-400 italic">null</span>';
                const newVal = newVals[f] !== undefined ? JSON.stringify(newVals[f]) : '<span class="text-slate-400 italic">null</span>';
                html += `
                    <tr class="hover:bg-slate-50 dark:hover:bg-slate-800/30">
                        <td class="px-3 py-2 font-bold text-slate-800 dark:text-slate-200">${escapeHtml(f)}</td>
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
        body.innerHTML = `
            <div class="space-y-3 font-mono">
                <div class="grid grid-cols-2 gap-2 text-[11px] p-3 bg-slate-50 dark:bg-slate-800/50 rounded-xl border border-slate-200 dark:border-slate-800">
                    <div><span class="text-slate-500">Method:</span> <strong class="text-slate-900 dark:text-white">${escapeHtml(audit.request_method)}</strong></div>
                    <div><span class="text-slate-500">IP Address:</span> <strong class="text-slate-900 dark:text-white">${escapeHtml(audit.ip_address)}</strong></div>
                    <div class="col-span-2"><span class="text-slate-500">URL:</span> <strong class="text-slate-900 dark:text-white">${escapeHtml(audit.request_url)}</strong></div>
                    <div class="col-span-2"><span class="text-slate-500">User Agent:</span> <span class="text-slate-700 dark:text-slate-300">${escapeHtml(audit.user_agent || 'N/A')}</span></div>
                </div>

                <div>
                    <h4 class="text-xs font-bold text-slate-700 dark:text-slate-300 mb-1">Sanitized HTTP Request Payload:</h4>
                    <pre class="p-3 rounded-xl bg-slate-950 text-emerald-400 text-[11px] overflow-x-auto border border-slate-800 max-h-96"><code>${escapeHtml(JSON.stringify(audit.payload_snapshot || {}, null, 2))}</code></pre>
                </div>
            </div>
        `;
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

    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') closeAuditModal();
    });
</script>
