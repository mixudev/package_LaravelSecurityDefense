<div id="metadataModal" class="fixed inset-0 z-50 hidden bg-zinc-950/60 backdrop-blur-xs flex items-center justify-center p-4">
    <div class="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 rounded-lg max-w-2xl w-full overflow-hidden">
        <div class="px-5 py-3 border-b border-zinc-200 dark:border-zinc-800 flex items-center justify-between">
            <h3 class="text-xs font-bold text-zinc-900 dark:text-white uppercase tracking-wider" id="modalTitle">Alert Telemetry</h3>
            <button type="button" onclick="closeMetadataModal()" class="text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200 text-lg font-bold cursor-pointer">&times;</button>
        </div>
        <div class="p-4">
            <pre id="modalContent" class="p-3.5 rounded-md bg-zinc-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 font-mono text-[11px] text-zinc-800 dark:text-zinc-200 overflow-x-auto max-h-96 leading-relaxed"></pre>
        </div>
        <div class="px-5 py-2.5 bg-zinc-50 dark:bg-zinc-950 border-t border-zinc-200 dark:border-zinc-800 flex justify-end">
            <button type="button" onclick="closeMetadataModal()" class="px-3 py-1.5 rounded-md bg-zinc-200 dark:bg-zinc-800 hover:bg-zinc-300 dark:hover:bg-zinc-700 text-zinc-800 dark:text-zinc-200 text-xs font-semibold cursor-pointer transition">
                Close
            </button>
        </div>
    </div>
</div>

<script>
    function showMetadataModal(alertId, rawJson) {
        document.getElementById('modalTitle').innerText = 'Sanitized Telemetry Metadata (Alert #' + alertId + ')';
        try {
            const parsed = JSON.parse(rawJson);
            document.getElementById('modalContent').innerText = JSON.stringify(parsed, null, 2);
        } catch (e) {
            document.getElementById('modalContent').innerText = rawJson;
        }
        document.getElementById('metadataModal').classList.remove('hidden');
    }

    function closeMetadataModal() {
        document.getElementById('metadataModal').classList.add('hidden');
    }

    // Close on Escape key press
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            closeMetadataModal();
        }
    });
</script>
