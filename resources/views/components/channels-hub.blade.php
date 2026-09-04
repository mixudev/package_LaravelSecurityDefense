@props([
    'channelsStatus' => [],
])

<section class="rounded-lg bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800 p-5">
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-100 dark:border-zinc-800 pb-4">
        <div>
            <h2 class="text-sm font-bold text-zinc-900 dark:text-white tracking-tight flex items-center space-x-2">
                <span>Notification Channels & Webhook Relay</span>
            </h2>
            <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">Safely test and verify connectivity across SIEM endpoints, chats, and emails.</p>
        </div>

        <!-- Test All Channels Button -->
        <form action="{{ route('security-defense.test-channel') }}" method="POST">
            @csrf
            <input type="hidden" name="channel" value="all">
            <button type="submit" class="w-full sm:w-auto inline-flex items-center justify-center px-3.5 py-1.5 rounded-md bg-zinc-900 dark:bg-zinc-100 hover:bg-zinc-800 dark:hover:bg-white text-white dark:text-zinc-900 text-xs font-bold transition cursor-pointer">
                <svg class="w-3.5 h-3.5 mr-1.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M6 12L3.269 3.126A59.768 59.768 0 0121.485 12 59.77 59.77 0 013.27 20.876L5.999 12zm0 0h7.5" />
                </svg>
                Test All Channels
            </button>
        </form>
    </div>

    <!-- Cards Grid -->
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-3.5 mt-4">
        @foreach($channelsStatus as $key => $status)
            @include('security-defense::components.channel-card', ['name' => $key, 'status' => $status])
        @endforeach
    </div>
</section>
