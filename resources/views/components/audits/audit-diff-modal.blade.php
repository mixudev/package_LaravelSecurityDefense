<!-- Interactive Diff & Payload Modal Component -->
<div id="audit-modal" class="fixed inset-0 z-50 hidden bg-zinc-950/70 backdrop-blur-xs flex items-center justify-center p-4" onclick="if(event.target === this) closeAuditModal()">
    <div class="bg-white dark:bg-[#121214] border border-zinc-200 dark:border-zinc-800 rounded-2xl max-w-4xl w-full max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
        <!-- Modal Header -->
        <div class="px-5 py-4 border-b border-zinc-200 dark:border-zinc-800 flex items-center justify-between bg-zinc-50/70 dark:bg-[#18181b]">
            <div class="min-w-0">
                <h3 id="modal-title" class="text-sm font-bold text-zinc-900 dark:text-zinc-100 truncate">Mutation Details</h3>
                <p id="modal-subtitle" class="text-xs text-zinc-500 dark:text-zinc-400 font-mono mt-0.5 truncate"></p>
            </div>
            <button type="button" aria-label="Close audit modal" onclick="closeAuditModal()" class="w-8 h-8 rounded-lg flex items-center justify-center text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200 hover:bg-zinc-100 dark:hover:bg-zinc-800 cursor-pointer text-lg font-bold flex-shrink-0 transition">
                &times;
            </button>
        </div>

        <!-- Modal Body -->
        <div id="modal-body" class="p-5 overflow-y-auto space-y-4 flex-1 text-xs"></div>

        <!-- Modal Footer -->
        <div class="px-5 py-3 border-t border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-[#18181b] flex justify-end gap-2">
            <button type="button" aria-label="Copy audit details" onclick="copyModalContent()" class="px-4 py-1.5 rounded-lg border border-zinc-300 dark:border-zinc-700 hover:bg-zinc-100 dark:hover:bg-zinc-800 text-zinc-700 dark:text-zinc-300 text-xs font-semibold cursor-pointer transition">
                Copy
            </button>
            <button type="button" aria-label="Close audit modal" onclick="closeAuditModal()" class="px-4 py-1.5 rounded-lg bg-zinc-200 hover:bg-zinc-300 dark:bg-zinc-800 dark:hover:bg-zinc-700 text-zinc-800 dark:text-zinc-200 text-xs font-semibold cursor-pointer transition">
                Close
            </button>
        </div>
    </div>
</div>

<script nonce="{{ request()->attributes->get('csp_nonce') }}">
    function parseAudit(auditData) {
        if (typeof auditData === 'object' && auditData !== null) return auditData;
        try {
            return JSON.parse(auditData);
        } catch (e) {
            console.error('Failed to parse audit payload', e);
            return {};
        }
    }

    function copyModalContent() {
        const body = document.getElementById('modal-body');
        const title = document.getElementById('modal-title').innerText;
        navigator.clipboard.writeText(title + '\n\n' + body.innerText).then(() => {
            const btn = event.target;
            const prev = btn.innerHTML;
            btn.innerHTML = 'Copied';
            setTimeout(() => btn.innerHTML = prev, 1200);
        });
    }

    function inspectDiff(rawAudit) {
        const audit = parseAudit(rawAudit);
        document.getElementById('modal-title').innerText = 'Attribute Diff - ' + ((audit.auditable_type || '').split('\\').pop()) + ' #' + (audit.auditable_id || '');
        document.getElementById('modal-subtitle').innerText = 'Event: ' + (audit.event ? audit.event.toUpperCase() : '') + ' | Actor: ' + (audit.actor_id ? 'User #' + audit.actor_id : 'System') + ' | ' + (audit.created_at || '');

        const body = document.getElementById('modal-body');
        let html = '';

        if (audit.is_tampered) {
            html += `
                <div class="p-3 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800">
                    <div class="font-bold flex items-center gap-2 text-xs text-rose-800 dark:text-rose-300">
                        <svg class="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                        </svg>
                        <span>Burp Suite Parameter Tampering Detected</span>
                    </div>
                    <ul class="list-disc list-inside mt-1.5 text-[11px] space-y-0.5 text-rose-700 dark:text-rose-300">
                        ${(audit.tamper_reasons || []).map(r => `<li>${escapeHtml(r)}</li>`).join('')}
                    </ul>
                </div>
            `;
        }

        const oldVals = audit.old_values || {};
        const newVals = audit.new_values || {};
        const fields = audit.modified_fields || Object.keys(Object.assign({}, oldVals, newVals));

        html += `
            <div class="border border-zinc-200 dark:border-zinc-800 rounded-xl overflow-hidden">
                <table class="min-w-full divide-y divide-zinc-200 dark:divide-zinc-800 text-left font-mono text-[11px]">
                    <thead class="bg-zinc-100 dark:bg-[#18181b] font-bold text-zinc-600 dark:text-zinc-400 uppercase tracking-wider text-[10px]">
                        <tr>
                            <th class="px-3 py-2 w-1/4">Field</th>
                            <th class="px-3 py-2 w-3/8 text-rose-600 dark:text-rose-400">Previous</th>
                            <th class="px-3 py-2 w-3/8 text-emerald-600 dark:text-emerald-400">Updated</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-zinc-200 dark:divide-zinc-800">
        `;

        if (fields.length === 0) {
            html += `<tr><td colspan="3" class="p-4 text-center text-zinc-400">No field changes captured.</td></tr>`;
        } else {
            fields.forEach(f => {
                const oldVal = oldVals[f] !== undefined ? escapeHtml(JSON.stringify(oldVals[f])) : '<span class="text-zinc-400 italic">null</span>';
                const newVal = newVals[f] !== undefined ? escapeHtml(JSON.stringify(newVals[f])) : '<span class="text-zinc-400 italic">null</span>';
                html += `
                    <tr class="hover:bg-zinc-50 dark:hover:bg-zinc-800/30 transition">
                        <td class="px-3 py-2 font-bold text-zinc-800 dark:text-zinc-200 align-top">${escapeHtml(f)}</td>
                        <td class="px-3 py-2 text-rose-700 dark:text-rose-300 bg-rose-50/20 dark:bg-rose-950/10 break-all align-top">${oldVal}</td>
                        <td class="px-3 py-2 text-emerald-700 dark:text-emerald-300 bg-emerald-50/20 dark:bg-emerald-950/10 break-all align-top">${newVal}</td>
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
        document.getElementById('modal-title').innerText = 'Request Payload Snapshot';
        document.getElementById('modal-subtitle').innerText = (audit.request_method || '') + ' ' + (audit.request_url || '') + ' | IP: ' + (audit.ip_address || '');
        document.getElementById('modal-subtitle').classList.remove('font-mono');

        const body = document.getElementById('modal-body');
        body.innerHTML = `
            <div class="space-y-3 font-mono">
                <div class="grid grid-cols-2 gap-x-4 gap-y-2 text-[11px] p-3 bg-zinc-50 dark:bg-[#18181b] rounded-xl border border-zinc-200 dark:border-zinc-800">
                    <div><span class="text-zinc-500">Method:</span> <strong class="text-zinc-900 dark:text-zinc-100">${escapeHtml(audit.request_method || 'N/A')}</strong></div>
                    <div><span class="text-zinc-500">IP Address:</span> <strong class="text-zinc-900 dark:text-zinc-100">${escapeHtml(audit.ip_address || 'N/A')}</strong></div>
                    <div class="col-span-2"><span class="text-zinc-500">URL:</span> <strong class="text-zinc-900 dark:text-zinc-100 break-all">${escapeHtml(audit.request_url || 'N/A')}</strong></div>
                    <div class="col-span-2"><span class="text-zinc-500">User Agent:</span> <span class="text-zinc-700 dark:text-zinc-300">${escapeHtml(audit.user_agent || 'N/A')}</span></div>
                </div>

                <div>
                    <h4 class="text-xs font-bold text-zinc-700 dark:text-zinc-300 mb-1.5 flex items-center gap-1.5">
                        <svg class="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/>
                        </svg>
                        Sanitized HTTP Request Payload
                    </h4>
                    <pre class="p-3 rounded-xl bg-zinc-950 text-emerald-400 text-[11px] overflow-x-auto border border-zinc-800 max-h-96 leading-relaxed"><code>${escapeHtml(JSON.stringify(audit.payload_snapshot || {}, null, 2))}</code></pre>
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