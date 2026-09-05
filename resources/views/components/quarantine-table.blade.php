@props([
    'quarantinedIps' => [],
])

@if(count($quarantinedIps) > 0)
    <section class="rounded-xl bg-white dark:bg-[#121214] border border-zinc-300/80 dark:border-zinc-800 p-4 sm:p-5 shadow-xs space-y-3.5">
        <div class="flex items-center justify-between">
            <div class="flex items-center space-x-3">
                <div class="w-8 h-8 rounded-lg bg-rose-50 dark:bg-rose-950/60 border border-rose-200 dark:border-rose-800 flex items-center justify-center text-rose-600 dark:text-rose-400 flex-shrink-0">
                    <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                    </svg>
                </div>
                <div>
                    <h3 class="text-sm font-bold text-zinc-900 dark:text-zinc-100 tracking-tight flex items-center space-x-2">
                        <span>Active IP Quarantines (Fail2Ban Defense)</span>
                        <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300">
                            {{ count($quarantinedIps) }} Jailed
                        </span>
                    </h3>
                    <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">Threat actors temporarily isolated from application network boundaries.</p>
                </div>
            </div>
        </div>

        <div class="overflow-x-auto rounded-lg border border-zinc-200 dark:border-zinc-800">
            <table class="min-w-full divide-y divide-zinc-200 dark:divide-zinc-800 text-left text-xs">
                <thead class="bg-zinc-50 dark:bg-[#18181b] font-bold text-zinc-600 dark:text-zinc-400 uppercase tracking-wider text-[10px]">
                    <tr>
                        <th class="px-4 py-3">Quarantined IP</th>
                        <th class="px-4 py-3">Violation Reason</th>
                        <th class="px-4 py-3">Jailed At</th>
                        <th class="px-4 py-3">Expires At</th>
                        <th class="px-4 py-3 text-right">Action</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-zinc-200 dark:divide-zinc-800/80 bg-white dark:bg-[#121214]">
                    @foreach($quarantinedIps as $jail)
                        <tr class="hover:bg-zinc-50/70 dark:hover:bg-zinc-800/40 transition">
                            <td class="px-4 py-3 font-mono font-bold text-rose-600 dark:text-rose-400">{{ $jail->ip }}</td>
                            <td class="px-4 py-3 text-zinc-700 dark:text-zinc-300">{{ $jail->reason }}</td>
                            <td class="px-4 py-3 text-zinc-500 dark:text-zinc-400 whitespace-nowrap">{{ $jail->jailed_at ? $jail->jailed_at->diffForHumans() : '—' }}</td>
                            <td class="px-4 py-3 text-zinc-500 dark:text-zinc-400 whitespace-nowrap">
                                @if($jail->expires_at)
                                    <span class="{{ $jail->expires_at->isPast() ? 'text-zinc-400 dark:text-zinc-500' : 'text-amber-600 dark:text-amber-400 font-semibold' }}">{{ $jail->expires_at->diffForHumans() }}</span>
                                @else
                                    —
                                @endif
                            </td>
                            <td class="px-4 py-3 text-right">
                                                            <form action="{{ route('security-defense.quarantine.whitelist') }}" method="POST" class="inline">
                                                                @csrf
                                                                <input type="hidden" name="ip" value="{{ $jail->ip }}">
                                                                <button type="submit" aria-label="Whitelist IP {{ $jail->ip }}" title="Whitelist {{ $jail->ip }} permanently"
                                                                    class="inline-flex items-center px-2.5 py-1.5 rounded-lg bg-zinc-100 hover:bg-zinc-200 text-zinc-600 hover:text-zinc-800 dark:bg-[#202024] dark:hover:bg-zinc-700 dark:text-zinc-300 dark:hover:text-zinc-100 border border-zinc-300 dark:border-zinc-700 transition cursor-pointer text-xs font-semibold shadow-xs">
                                                                    <svg class="w-3.5 h-3.5 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                                                        <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                                                                    </svg>
                                                                    Whitelist
                                                                </button>
                                                            </form>
                                                            <form action="{{ route('security-defense.quarantine.pardon') }}" method="POST" class="inline">
                                                                @csrf
                                                                <input type="hidden" name="ip" value="{{ $jail->ip }}">
                                                                <button type="submit" aria-label="Release IP {{ $jail->ip }} from quarantine" title="Release {{ $jail->ip }}"
                                                                    class="inline-flex items-center px-2.5 py-1.5 rounded-lg bg-zinc-100 hover:bg-emerald-100 text-zinc-700 hover:text-emerald-800 dark:bg-[#202024] dark:hover:bg-emerald-950 dark:text-zinc-200 dark:hover:text-emerald-400 border border-zinc-300 dark:border-zinc-700 transition cursor-pointer text-xs font-semibold shadow-xs">
                                                                    <svg class="w-3.5 h-3.5 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                                                        <path stroke-linecap="round" stroke-linejoin="round" d="M13.5 10.5V6.75a4.5 4.5 0 119 0v3.75M3.75 21.75h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H3.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" />
                                                                    </svg>
                                                                    Release
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
