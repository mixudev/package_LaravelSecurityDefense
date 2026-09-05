<header class="sticky top-0 z-30 border-b border-zinc-200 dark:border-zinc-800 bg-white/95 dark:bg-zinc-950/95 backdrop-blur-md">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="flex items-center justify-between h-16">
            <!-- Left: Brand -->
            <div class="flex items-center space-x-3">
                <a href="{{ route('security-defense.dashboard') }}" class="flex items-center space-x-3 group">
                    <div class="w-9 h-9 rounded-md bg-zinc-900 dark:bg-zinc-100 flex items-center justify-center text-white dark:text-zinc-950 font-bold group-hover:scale-105 transition">
                        <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                        </svg>
                    </div>
                    <div>
                        <div class="flex items-center space-x-2">
                            <span class="text-sm font-bold tracking-tight text-zinc-900 dark:text-white">Security Defense</span>
                            <span class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300 border border-zinc-300 dark:border-zinc-700 font-mono">
                                SIEM
                            </span>
                        </div>
                        <p class="text-[11px] text-zinc-500 dark:text-zinc-400">Proactive Threat Telemetry & Monitoring</p>
                    </div>
                </a>
            </div>

            <!-- Center: Navigation Tabs (Desktop) -->
            <nav class="hidden md:flex items-center space-x-1 font-sans text-xs">
                @php
                    $currentRoute = request()->route()?->getName();
                @endphp

                <!-- 1. Threat Telemetry -->
                <a href="{{ route('security-defense.dashboard') }}"
                   class="inline-flex items-center px-3 py-2 rounded-md transition font-medium {{ $currentRoute === 'security-defense.dashboard' ? 'bg-zinc-100 dark:bg-zinc-800/80 text-zinc-900 dark:text-white border border-zinc-200 dark:border-zinc-700 shadow-xs' : 'text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-white hover:bg-zinc-50 dark:hover:bg-zinc-900' }}">
                    <svg class="w-4 h-4 mr-1.5 opacity-80" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z" />
                    </svg>
                    <span>Threat Telemetry</span>
                </a>

                <!-- 2. Database Changes (Data Audits) -->
                <a href="{{ route('security-defense.data-audits') }}"
                   class="inline-flex items-center px-3 py-2 rounded-md transition font-medium {{ $currentRoute === 'security-defense.data-audits' ? 'bg-zinc-100 dark:bg-zinc-800/80 text-zinc-900 dark:text-white border border-zinc-200 dark:border-zinc-700 shadow-xs' : 'text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-white hover:bg-zinc-50 dark:hover:bg-zinc-900' }}">
                    <svg class="w-4 h-4 mr-1.5 opacity-80" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M20.25 6.375c0 2.278-3.694 4.125-8.25 4.125S3.75 8.653 3.75 6.375m16.5 0c0-2.278-3.694-4.125-8.25-4.125S3.75 4.097 3.75 6.375m16.5 0v11.25c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125V6.375m16.5 5.625c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125" />
                    </svg>
                    <span>Database Mutations</span>
                </a>

                <!-- 3. Session & Device Intelligence -->
                <a href="{{ route('security-defense.sessions') }}"
                   class="inline-flex items-center px-3 py-2 rounded-md transition font-medium {{ $currentRoute === 'security-defense.sessions' ? 'bg-zinc-100 dark:bg-zinc-800/80 text-zinc-900 dark:text-white border border-zinc-200 dark:border-zinc-700 shadow-xs' : 'text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-white hover:bg-zinc-50 dark:hover:bg-zinc-900' }}">
                    <svg class="w-4 h-4 mr-1.5 opacity-80" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M10.5 1.5H8.25A2.25 2.25 0 006 3.75v16.5a2.25 2.25 0 002.25 2.25h7.5A2.25 2.25 0 0018 20.25V3.75a2.25 2.25 0 00-2.25-2.25H13.5m-3 0V3h3V1.5m-3 0h3m-3 18.75h3" />
                    </svg>
                    <span>Session Intelligence</span>
                </a>
            </nav>

            <!-- Right: Controls & Badges -->
            <div class="flex items-center space-x-2">
                <!-- Local Status Pill -->
                <div class="hidden sm:inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-md bg-emerald-50 dark:bg-emerald-950/50 border border-emerald-300 dark:border-emerald-800 text-emerald-700 dark:text-emerald-400 text-xs font-medium">
                    <span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
                    <span>Strict Local Mode Active</span>
                </div>

                <!-- Theme Toggle Button -->
                <button type="button" onclick="toggleTheme()" class="p-2 rounded-md border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-white hover:bg-zinc-100 dark:hover:bg-zinc-800 transition cursor-pointer" title="Toggle Light/Dark Theme">
                    <!-- Sun Icon (Shown in Dark Mode) -->
                    <svg id="theme-icon-sun" class="w-4 h-4 hidden" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M12 3v2.25m6.364.386l-1.591 1.591M21 12h-2.25m-.386 6.364l-1.591-1.591M12 18.75V21m-4.773-4.227l-1.591 1.591M5.25 12H3m4.227-4.773L5.636 5.636M15.75 12a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0z" />
                    </svg>
                    <!-- Moon Icon (Shown in Light Mode) -->
                    <svg id="theme-icon-moon" class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M21.752 15.002A9.718 9.718 0 0118 15.75c-5.385 0-9.75-4.365-9.75-9.75 0-1.33.266-2.597.748-3.752A9.753 9.753 0 003 11.25C3 16.635 7.365 21 12.75 21a9.753 9.753 0 009.002-5.998z" />
                    </svg>
                </button>

                <!-- Refresh Button -->
                <a href="{{ url()->current() }}" class="p-2 rounded-md border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-white hover:bg-zinc-100 dark:hover:bg-zinc-800 transition cursor-pointer" title="Refresh Telemetry">
                    <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99" />
                    </svg>
                </a>
            </div>
        </div>

        <!-- Mobile Navigation Bar -->
        <div class="flex md:hidden border-t border-zinc-200 dark:border-zinc-800 py-2 space-x-2 overflow-x-auto text-xs font-sans">
            <a href="{{ route('security-defense.dashboard') }}"
               class="px-2.5 py-1.5 rounded-md whitespace-nowrap {{ $currentRoute === 'security-defense.dashboard' ? 'bg-zinc-200 dark:bg-zinc-800 font-semibold text-zinc-900 dark:text-white' : 'text-zinc-600 dark:text-zinc-400' }}">
                Threat Telemetry
            </a>
            <a href="{{ route('security-defense.data-audits') }}"
               class="px-2.5 py-1.5 rounded-md whitespace-nowrap {{ $currentRoute === 'security-defense.data-audits' ? 'bg-zinc-200 dark:bg-zinc-800 font-semibold text-zinc-900 dark:text-white' : 'text-zinc-600 dark:text-zinc-400' }}">
                Database Mutations
            </a>
            <a href="{{ route('security-defense.sessions') }}"
               class="px-2.5 py-1.5 rounded-md whitespace-nowrap {{ $currentRoute === 'security-defense.sessions' ? 'bg-zinc-200 dark:bg-zinc-800 font-semibold text-zinc-900 dark:text-white' : 'text-zinc-600 dark:text-zinc-400' }}">
                Session Intelligence
            </a>
        </div>
    </div>
</header>
