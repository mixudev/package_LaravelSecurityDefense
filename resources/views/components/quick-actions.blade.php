@props([
    'blockHeadless' => false,
    'cspArmor' => true,
    'asyncQueue' => false,
])

<section class="rounded-xl bg-white dark:bg-[#121214] border border-zinc-300/80 dark:border-zinc-800 p-4 sm:p-5 space-y-4 shadow-xs">
    <div class="flex items-center justify-between">
        <div class="flex items-center space-x-3">
            <div class="w-8 h-8 rounded-lg bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200 dark:border-emerald-800 flex items-center justify-center text-emerald-600 dark:text-emerald-400 flex-shrink-0">
                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M11.42 15.17L17.25 21A2.652 2.652 0 0021 17.25l-5.877-5.877M11.42 15.17l2.496-3.03c.317-.384.74-.626 1.208-.766M11.42 15.17l-4.655 5.653a2.548 2.548 0 11-3.586-3.586l6.837-5.63m5.108-.233c.55-.164 1.163-.188 1.743-.14a4.5 4.5 0 004.486-6.336l-3.276 3.277a3.004 3.004 0 01-2.25-2.25l3.276-3.276a4.5 4.5 0 00-6.336 4.486c.091 1.076-.071 2.264-.904 2.95l-.102.085m-1.745 1.437L5.909 7.5H4.5L2.25 3.75l1.5-1.5L7.5 4.5v1.409l4.26 4.26m-1.745 1.437l1.745-1.437m6.615 8.206L15.75 15.75M4.867 19.125h.008v.008h-.008v-.008z" />
                </svg>
            </div>
            <div>
                <h3 class="text-sm font-bold text-zinc-900 dark:text-zinc-100 tracking-tight">Quick Actions</h3>
                <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">Toggle key defenses live. Changes persist to config file.</p>
            </div>
        </div>
    </div>

    <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <!-- Block Headless Clients -->
        <form method="POST" action="{{ route('security-defense.toggle-setting') }}" class="rounded-lg border border-zinc-200 dark:border-zinc-800 p-3 flex items-center justify-between gap-3 hover:bg-zinc-50 dark:hover:bg-zinc-800/30 transition">
            @csrf
            <input type="hidden" name="key" value="block_headless_clients">
            <input type="hidden" name="value" value="{{ $blockHeadless ? '0' : '1' }}">
            <div class="min-w-0">
                <div class="text-xs font-semibold text-zinc-800 dark:text-zinc-200">Block Headless Clients</div>
                <div class="text-[10px] text-zinc-500 dark:text-zinc-400 mt-0.5">Reject curl / python-requests / headless bots</div>
            </div>
            <button type="submit" role="switch" aria-checked="{{ $blockHeadless ? 'true' : 'false' }}" title="Toggle block headless clients"
                class="relative inline-flex flex-shrink-0 w-9 h-5 rounded-full transition cursor-pointer {{ $blockHeadless ? 'bg-emerald-500' : 'bg-zinc-300 dark:bg-zinc-700' }}">
                <span class="inline-block w-3.5 h-3.5 rounded-full bg-white shadow transform transition" style="{{ $blockHeadless ? 'transform: translateX(16px);' : 'transform: translateX(2px);' }}"></span>
            </button>
        </form>

        <!-- CSP Armor -->
        <form method="POST" action="{{ route('security-defense.toggle-setting') }}" class="rounded-lg border border-zinc-200 dark:border-zinc-800 p-3 flex items-center justify-between gap-3 hover:bg-zinc-50 dark:hover:bg-zinc-800/30 transition">
            @csrf
            <input type="hidden" name="key" value="csp_armor">
            <input type="hidden" name="value" value="{{ $cspArmor ? '0' : '1' }}">
            <div class="min-w-0">
                <div class="text-xs font-semibold text-zinc-800 dark:text-zinc-200">CSP Armor</div>
                <div class="text-[10px] text-zinc-500 dark:text-zinc-400 mt-0.5">Strict Content-Security-Policy nonce headers</div>
            </div>
            <button type="submit" role="switch" aria-checked="{{ $cspArmor ? 'true' : 'false' }}" title="Toggle CSP armor"
                class="relative inline-flex flex-shrink-0 w-9 h-5 rounded-full transition cursor-pointer {{ $cspArmor ? 'bg-emerald-500' : 'bg-zinc-300 dark:bg-zinc-700' }}">
                <span class="inline-block w-3.5 h-3.5 rounded-full bg-white shadow transform transition mt-0.5 {{ $cspArmor ? 'translate-x-4.5 ml-0.5' : 'translate-x-0.5' }}"></span>
            </button>
        </form>

        <!-- Async Queue -->
        <form method="POST" action="{{ route('security-defense.toggle-setting') }}" class="rounded-lg border border-zinc-200 dark:border-zinc-800 p-3 flex items-center justify-between gap-3 hover:bg-zinc-50 dark:hover:bg-zinc-800/30 transition">
            @csrf
            <input type="hidden" name="key" value="async_queue">
            <input type="hidden" name="value" value="{{ $asyncQueue ? '0' : '1' }}">
            <div class="min-w-0">
                <div class="text-xs font-semibold text-zinc-800 dark:text-zinc-200">Async Audit Queue</div>
                <div class="text-[10px] text-zinc-500 dark:text-zinc-400 mt-0.5">Background queue for data audit logs</div>
            </div>
            <button type="submit" role="switch" aria-checked="{{ $asyncQueue ? 'true' : 'false' }}" title="Toggle async audit queue"
                class="relative inline-flex flex-shrink-0 w-9 h-5 rounded-full transition cursor-pointer {{ $asyncQueue ? 'bg-emerald-500' : 'bg-zinc-300 dark:bg-zinc-700' }}">
                <span class="inline-block w-3.5 h-3.5 rounded-full bg-white shadow transform transition mt-0.5 {{ $asyncQueue ? 'translate-x-4.5 ml-0.5' : 'translate-x-0.5' }}"></span>
            </button>
        </form>
    </div>
</section>