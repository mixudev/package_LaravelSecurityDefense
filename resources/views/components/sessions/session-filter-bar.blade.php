@props([
    'filters' => [],
])

<div class="bg-white dark:bg-[#121214] border border-zinc-200/90 dark:border-zinc-800 rounded-xl p-4 shadow-xs">
    <form method="GET" action="{{ route('security-defense.sessions') }}" class="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <!-- Threat Type -->
        <div>
            <label class="block text-[11px] font-medium text-zinc-500 dark:text-zinc-400 mb-1">Threat Classification</label>
            <select name="threat_type" class="w-full px-3 py-1.5 text-xs rounded-lg border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-[#18181b] text-zinc-900 dark:text-zinc-100 focus:ring-2 focus:ring-emerald-500/20 focus:outline-none">
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
            <select name="severity" class="w-full px-3 py-1.5 text-xs rounded-lg border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-[#18181b] text-zinc-900 dark:text-zinc-100 focus:ring-2 focus:ring-emerald-500/20 focus:outline-none">
                <option value="">All Severities</option>
                <option value="critical" {{ ($filters['severity'] ?? '') === 'critical' ? 'selected' : '' }}>Critical</option>
                <option value="high" {{ ($filters['severity'] ?? '') === 'high' ? 'selected' : '' }}>High</option>
                <option value="medium" {{ ($filters['severity'] ?? '') === 'medium' ? 'selected' : '' }}>Medium</option>
                <option value="low" {{ ($filters['severity'] ?? '') === 'low' ? 'selected' : '' }}>Low</option>
            </select>
        </div>

        <!-- Actions -->
        <div class="flex items-end space-x-2">
            <button type="submit" class="flex-1 px-3 py-1.5 bg-zinc-900 dark:bg-zinc-100 hover:bg-zinc-800 dark:hover:bg-white text-white dark:text-zinc-900 rounded-lg text-xs font-semibold transition cursor-pointer shadow-xs">
                Filter
            </button>
            <a href="{{ route('security-defense.sessions') }}" class="px-3 py-1.5 border border-zinc-300 dark:border-zinc-700 hover:bg-zinc-100 dark:hover:bg-zinc-800 text-zinc-700 dark:text-zinc-300 rounded-lg text-xs font-semibold transition cursor-pointer">
                Reset
            </a>
        </div>
    </form>
</div>