@props([
    'filters' => [],
])

<div class="bg-white dark:bg-[#121214] border border-zinc-200/90 dark:border-zinc-800 rounded-xl p-4 shadow-xs">
    <form method="GET" action="{{ route('security-defense.data-audits') }}" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
        <!-- Search -->
        <div>
            <label class="block text-[11px] font-medium text-zinc-500 dark:text-zinc-400 mb-1">Search Identifier / URL / IP</label>
            <input type="text" name="search" value="{{ $filters['search'] ?? '' }}" placeholder="e.g. 192.168.1.1, /admin/users..."
                   class="w-full px-3 py-1.5 text-xs rounded-lg border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-[#18181b] text-zinc-900 dark:text-zinc-100 focus:ring-2 focus:ring-emerald-500/20 focus:outline-none">
        </div>

        <!-- Event -->
        <div>
            <label class="block text-[11px] font-medium text-zinc-500 dark:text-zinc-400 mb-1">Mutation Event</label>
            <select name="event" class="w-full px-3 py-1.5 text-xs rounded-lg border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-[#18181b] text-zinc-900 dark:text-zinc-100 focus:ring-2 focus:ring-emerald-500/20 focus:outline-none">
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
                   class="w-full px-3 py-1.5 text-xs rounded-lg border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-[#18181b] text-zinc-900 dark:text-zinc-100 focus:ring-2 focus:ring-emerald-500/20 focus:outline-none">
        </div>

        <!-- Tampering Status -->
        <div>
            <label class="block text-[11px] font-medium text-zinc-500 dark:text-zinc-400 mb-1">Integrity Status</label>
            <select name="tampered" class="w-full px-3 py-1.5 text-xs rounded-lg border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-[#18181b] text-zinc-900 dark:text-zinc-100 focus:ring-2 focus:ring-emerald-500/20 focus:outline-none">
                <option value="">All Records</option>
                <option value="1" {{ ($filters['tampered'] ?? '') === '1' ? 'selected' : '' }}>[!] Tamper Detected Only</option>
                <option value="0" {{ ($filters['tampered'] ?? '') === '0' ? 'selected' : '' }}>Clean Only</option>
            </select>
        </div>

        <!-- Actions -->
        <div class="flex items-end space-x-2">
            <button type="submit" class="flex-1 px-3 py-1.5 bg-zinc-900 dark:bg-zinc-100 hover:bg-zinc-800 dark:hover:bg-white text-white dark:text-zinc-900 rounded-lg text-xs font-semibold transition cursor-pointer shadow-xs">
                Apply Filter
            </button>
            <a href="{{ route('security-defense.data-audits') }}" class="px-3 py-1.5 border border-zinc-300 dark:border-zinc-700 hover:bg-zinc-100 dark:hover:bg-zinc-800 text-zinc-700 dark:text-zinc-300 rounded-lg text-xs font-semibold transition cursor-pointer">
                Reset
            </a>
        </div>
    </form>
</div>