<div id="metadataModal" class="fixed inset-0 z-50 hidden bg-slate-950/70 backdrop-blur-md flex items-center justify-center p-4 transition-all duration-200">
    <div class="bg-white dark:bg-[#0f172a] border border-slate-200 dark:border-slate-800 rounded-2xl max-w-2xl w-full overflow-hidden shadow-2xl transform transition-all">
        <!-- Modal Header -->
        <div class="px-5 py-3.5 border-b border-slate-200/90 dark:border-slate-800 flex items-center justify-between bg-slate-50/70 dark:bg-slate-900/60">
            <div class="flex items-center space-x-2.5">
                <div class="w-7 h-7 rounded-lg bg-indigo-600/10 dark:bg-indigo-500/20 text-indigo-600 dark:text-indigo-400 flex items-center justify-center">
                    <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M11.25 11.25l.041-.02a.75.75 0 011.063.852l-.708 2.836a.75.75 0 001.063.853l.041-.021M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3.75h.008v.008H12V8.25z" />
                    </svg>
                </div>
                <div>
                    <h3 class="text-xs font-bold text-slate-900 dark:text-white uppercase tracking-wider" id="modalTitle">Incident Telemetry Payload</h3>
                    <p class="text-[10px] text-slate-500 dark:text-slate-400">Neutralized JSON telemetry data captured during event correlation.</p>
                </div>
            </div>

            <div class="flex items-center space-x-2">
                <!-- Copy JSON button -->
                <button type="button" id="copyTelemetryBtn" onclick="copyTelemetryJson()" class="inline-flex items-center px-2.5 py-1 rounded-md text-[11px] font-semibold bg-white hover:bg-slate-100 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 border border-slate-200 dark:border-slate-700 transition cursor-pointer shadow-xs">
                    <svg id="copyIcon" class="w-3.5 h-3.5 mr-1 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                    </svg>
                    <span id="copyText">Copy Payload</span>
                </button>

                <button type="button" onclick="closeMetadataModal()" class="w-7 h-7 rounded-lg flex items-center justify-center text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition cursor-pointer font-bold text-base">
                    &times;
                </button>
            </div>
        </div>

        <!-- Defanged Security Notice -->
        <div class="bg-amber-50 dark:bg-amber-950/30 border-b border-amber-200/80 dark:border-amber-900/50 px-5 py-2 flex items-center justify-between text-[11px] text-amber-800 dark:text-amber-300 font-mono">
            <span class="flex items-center space-x-1.5">
                <svg class="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                </svg>
                <span>Sanitized & Defanged: Dangerous executable entities are safe for display.</span>
            </span>
            <span class="font-bold text-[10px] uppercase tracking-wider bg-amber-200/60 dark:bg-amber-900/60 px-1.5 py-0.5 rounded text-amber-900 dark:text-amber-200">AST Protected</span>
        </div>

        <!-- JSON Code Container -->
        <div class="p-4 bg-slate-900 dark:bg-black">
            <pre id="modalContent" class="p-3.5 rounded-xl bg-slate-950 border border-slate-800 font-mono text-[11px] text-emerald-400 overflow-x-auto max-h-96 leading-relaxed selection:bg-indigo-900 selection:text-white"></pre>
        </div>

        <!-- Modal Footer -->
        <div class="px-5 py-3 bg-slate-50 dark:bg-slate-900 border-t border-slate-200 dark:border-slate-800 flex justify-between items-center text-xs">
            <span class="text-[11px] text-slate-500 dark:text-slate-400 font-mono">Press [Esc] to exit</span>
            <button type="button" onclick="closeMetadataModal()" class="px-3.5 py-1.5 rounded-lg bg-slate-200 hover:bg-slate-300 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 text-xs font-semibold cursor-pointer transition">
                Close
            </button>
        </div>
    </div>
</div>

<script>
    let currentRawTelemetry = '';

    function showMetadataModal(alertId, rawJson) {
        currentRawTelemetry = rawJson;
        document.getElementById('modalTitle').innerText = 'Telemetry Details &bull; Alert #' + alertId;
        try {
            const parsed = JSON.parse(rawJson);
            document.getElementById('modalContent').innerText = JSON.stringify(parsed, null, 2);
        } catch (e) {
            document.getElementById('modalContent').innerText = rawJson;
        }

        // Reset copy button state
        const copyText = document.getElementById('copyText');
        if (copyText) copyText.innerText = 'Copy Payload';

        document.getElementById('metadataModal').classList.remove('hidden');
    }

    function closeMetadataModal() {
        document.getElementById('metadataModal').classList.add('hidden');
    }

    function copyTelemetryJson() {
        const textToCopy = document.getElementById('modalContent').innerText;
        navigator.clipboard.writeText(textToCopy).then(function() {
            const copyText = document.getElementById('copyText');
            if (copyText) {
                copyText.innerText = '✓ Copied!';
                setTimeout(() => {
                    copyText.innerText = 'Copy Payload';
                }, 2000);
            }
        }).catch(function(err) {
            console.error('Could not copy telemetry: ', err);
        });
    }

    // Close on Escape key press
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            closeMetadataModal();
        }
    });
</script>
