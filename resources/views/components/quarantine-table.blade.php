@props([
    'quarantinedIps' => [],
])

@if(count($quarantinedIps) > 0)
    <section class="rounded-lg bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 p-5">
        <div class="flex items-center justify-between mb-3.5">
            <div>
                <h3 class="text-sm font-bold text-zinc-900 dark:text-white tracking-tight flex items-center space-x-2">
                    <span class="text-rose-600 dark:text-rose-400">⛔</span>
                    <span>Active IP Quarantines (Fail2Ban Defense)</span>
                </h3>
                <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">Threat actors temporarily isolated from application network boundaries.</p>
            </div>
        </div>

        <div class="overflow-x-auto rounded-md border border-zinc-200 dark:border-zinc-800">
            <table class="min-w-full divide-y divide-zinc-200 dark:divide-zinc-800 text-left text-xs">
                <thead class="bg-zinc-50 dark:bg-zinc-950 font-semibold text-zinc-600 dark:text-zinc-400 uppercase tracking-wider text-[10px]">
                    <tr>
                        <th class="px-3.5 py-2.5">Quarantined IP</th>
                        <th class="px-3.5 py-2.5">Violation Reason</th>
                        <th class="px-3.5 py-2.5">Jailed At</th>
                        <th class="px-3.5 py-2.5">Expires At</th>
                        <th class="px-3.5 py-2.5 text-right">Action</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-zinc-200 dark:divide-zinc-800/80 bg-white dark:bg-zinc-900/60">
                    @foreach($quarantinedIps as $jail)
                        <tr class="hover:bg-zinc-50 dark:hover:bg-zinc-800/40 transition">
                            <td class="px-3.5 py-2.5 font-mono font-bold text-rose-600 dark:text-rose-400">{{ $jail->ip }}</td>
                            <td class="px-3.5 py-2.5 text-zinc-700 dark:text-zinc-300">{{ $jail->reason }}</td>
                            <td class="px-3.5 py-2.5 text-zinc-500 dark:text-zinc-400">{{ $jail->jailed_at }}</td>
                            <td class="px-3.5 py-2.5 text-zinc-500 dark:text-zinc-400">{{ $jail->expires_at }}</td>
                            <td class="px-3.5 py-2.5 text-right">
                                <form action="{{ route('security-defense.quarantine.pardon') }}" method="POST" class="inline">
                                    @csrf
                                    <input type="hidden" name="ip" value="{{ $jail->ip }}">
                                    <button type="submit" class="px-2.5 py-1 rounded bg-zinc-100 hover:bg-emerald-100 text-zinc-700 hover:text-emerald-800 dark:bg-zinc-800 dark:hover:bg-emerald-950 dark:text-zinc-300 dark:hover:text-emerald-400 border border-zinc-200 dark:border-zinc-700 transition cursor-pointer text-xs font-medium">
                                        Release IP
                                    </button>
                                </form>
                            </td>
                        </tr>
                    @endforeach
                </tbody>
            </table>
        </div>
    </section>
@endif
