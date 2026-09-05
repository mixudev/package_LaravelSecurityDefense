@props([
    'events' => [],
    'pollInterval' => 5000,
])

<section class="rounded-xl bg-white dark:bg-[#121214] border border-zinc-300/80 dark:border-zinc-800 p-4 sm:p-5 space-y-3 shadow-xs">
    <div class="flex items-center justify-between">
        <div class="flex items-center space-x-3">
            <div class="w-8 h-8 rounded-lg bg-amber-50 dark:bg-amber-950/60 border border-amber-200 dark:border-amber-800 flex items-center justify-center text-amber-600 dark:text-amber-400 flex-shrink-0">
                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z" />
                </svg>
            </div>
            <div>
                <h3 class="text-sm font-bold text-zinc-900 dark:text-zinc-100 tracking-tight flex items-center space-x-2">
                    <span>Live WAF Events</span>
                    <span class="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-400">
                        <span class="w-1.5 h-1.5 rounded-full bg-emerald-500 mr-1 animate-pulse"></span>
                        LIVE
                    </span>
                </h3>
                <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">Most recent blocked requests. Auto-refreshes every 5s.</p>
            </div>
        </div>
        <span class="text-[11px] font-mono px-2 py-0.5 rounded bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400 font-semibold" id="live-events-count">
            {{ count($events) }} Events
        </span>
    </div>

    <div class="overflow-x-auto rounded-lg border border-zinc-200 dark:border-zinc-800">
        <table class="min-w-full divide-y divide-zinc-200 dark:divide-zinc-800 text-left text-xs">
            <thead class="bg-zinc-50 dark:bg-[#18181b] font-bold text-zinc-600 dark:text-zinc-400 uppercase tracking-wider text-[10px]">
                <tr>
                    <th class="px-4 py-3">Severity</th>
                    <th class="px-4 py-3">Threat Type</th>
                    <th class="px-4 py-3">Source IP</th>
                    <th class="px-4 py-3">Request</th>
                    <th class="px-4 py-3">Detected</th>
                </tr>
            </thead>
            <tbody id="live-events-body" class="divide-y divide-zinc-200 dark:divide-zinc-800/80 bg-white dark:bg-[#121214]">
                @forelse($events as $event)
                    <tr class="hover:bg-zinc-50/70 dark:hover:bg-zinc-800/40 transition">
                        <td class="px-4 py-3 whitespace-nowrap">
                            <span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold font-mono uppercase
                                @if($event['severity'] === 'critical') bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300 border border-rose-300 dark:border-rose-800
                                @elseif($event['severity'] === 'high') bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-300 border border-orange-300 dark:border-orange-800
                                @elseif($event['severity'] === 'medium') bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300 border border-amber-300 dark:border-amber-800
                                @else bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300 border border-zinc-300 dark:border-zinc-700 @endif">
                                {{ $event['severity'] }}
                            </span>
                        </td>
                        <td class="px-4 py-3 font-mono text-zinc-700 dark:text-zinc-300">{{ $event['threat_type'] }}</td>
                        <td class="px-4 py-3 font-mono text-zinc-600 dark:text-zinc-400">{{ $event['ip'] }}</td>
                        <td class="px-4 py-3">
                            <span class="inline-flex items-center space-x-1.5 max-w-xs">
                                <span class="font-mono text-[10px] font-bold px-1 rounded bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300 border border-zinc-200 dark:border-zinc-700">{{ $event['method'] }}</span>
                                <span class="font-mono text-[11px] text-zinc-600 dark:text-zinc-300 truncate" title="{{ $event['url'] }}">{{ Str::limit($event['url'], 40) }}</span>
                            </span>
                        </td>
                        <td class="px-4 py-3 font-mono text-[11px] text-zinc-500 dark:text-zinc-400 whitespace-nowrap">
                            {{ \Illuminate\Support\Carbon::parse($event['created_at'])->diffForHumans() }}
                        </td>
                    </tr>
                @empty
                    <tr>
                        <td colspan="5" class="px-4 py-10 text-center text-zinc-400 dark:text-zinc-500 text-xs">
                            No blocked requests in the recent window. All traffic within safety margins.
                        </td>
                    </tr>
                @endforelse
            </tbody>
        </table>
    </div>
</section>

@push('scripts')
<script>
    document.addEventListener('DOMContentLoaded', function() {
        const url = @json(route('security-defense.live-events'));
        const tbody = document.getElementById('live-events-body');
        if (!tbody) return;

        async function refreshLiveEvents() {
            try {
                const res = await fetch(url, { headers: { 'Accept': 'application/json' }, cache: 'no-store' });
                if (!res.ok) return;
                const data = await res.json();
                const countEl = document.getElementById('live-events-count');
                if (countEl) countEl.textContent = data.events.length + ' Events';

                tbody.innerHTML = data.events.map(function(e) {
                    const sevClass = e.severity === 'critical'
                        ? 'bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300 border border-rose-300 dark:border-rose-800'
                        : e.severity === 'high'
                            ? 'bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-300 border border-orange-300 dark:border-orange-800'
                            : e.severity === 'medium'
                                ? 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300 border border-amber-300 dark:border-amber-800'
                                : 'bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300 border border-zinc-300 dark:border-zinc-700';
                    return `<tr class="hover:bg-zinc-50/70 dark:hover:bg-zinc-800/40 transition">
                        <td class="px-4 py-3 whitespace-nowrap"><span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold font-mono uppercase ${sevClass}">${e.severity}</span></td>
                        <td class="px-4 py-3 font-mono text-zinc-700 dark:text-zinc-300">${escapeHtml(e.threat_type)}</td>
                        <td class="px-4 py-3 font-mono text-zinc-600 dark:text-zinc-400">${escapeHtml(e.ip)}</td>
                        <td class="px-4 py-3"><span class="inline-flex items-center space-x-1.5 max-w-xs"><span class="font-mono text-[10px] font-bold px-1 rounded bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300 border border-zinc-200 dark:border-zinc-700">${escapeHtml(e.method)}</span><span class="font-mono text-[11px] text-zinc-600 dark:text-zinc-300 truncate" title="${escapeHtml(e.url)}">${escapeHtml(e.url.length > 40 ? e.url.slice(0, 40) + '...' : e.url)}</span></span></td>
                        <td class="px-4 py-3 font-mono text-[11px] text-zinc-500 dark:text-zinc-400 whitespace-nowrap">${timeAgo(e.created_at)}</td>
                    </tr>`;
                }).join('');

                if (data.events.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="5" class="px-4 py-10 text-center text-zinc-400 dark:text-zinc-500 text-xs">No blocked requests in the recent window. All traffic within safety margins.</td></tr>`;
                }
            } catch (err) {
                // Silent: keep previous rows on transient network errors.
            }
        }

        function escapeHtml(str) {
            if (!str) return '';
            return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
        }

        function timeAgo(iso) {
            const then = new Date(iso);
            const diff = Math.floor((Date.now() - then.getTime()) / 1000);
            if (diff < 5) return 'just now';
            if (diff < 60) return diff + 's ago';
            if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
            return new Date(iso).toLocaleString();
        }

        setInterval(refreshLiveEvents, @json($pollInterval));
    });
</script>
@endpush