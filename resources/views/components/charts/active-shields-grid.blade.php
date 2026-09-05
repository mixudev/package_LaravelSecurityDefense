<!-- Active Defensive Subsystems Grid Component -->
<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
    <!-- Shield 1: Dynamic WAF -->
    <div class="p-3 rounded-xl bg-white dark:bg-[#0f172a] border border-slate-200/90 dark:border-slate-800 flex items-center space-x-3 shadow-xs">
        <div class="w-8 h-8 rounded-lg bg-indigo-50 dark:bg-indigo-950/60 border border-indigo-200 dark:border-indigo-800 flex items-center justify-center text-indigo-600 dark:text-indigo-400 flex-shrink-0">
            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
            </svg>
        </div>
        <div class="min-w-0 flex-1">
            <div class="flex items-center justify-between">
                <span class="text-xs font-bold text-slate-900 dark:text-white">Request Threat WAF</span>
                <span class="px-1.5 py-0.2 rounded text-[9px] font-bold bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-400">ACTIVE</span>
            </div>
            <p class="text-[10px] text-slate-500 dark:text-slate-400 truncate">AST injection & payload scanning</p>
        </div>
    </div>

    <!-- Shield 2: Fail2Ban Jail -->
    <div class="p-3 rounded-xl bg-white dark:bg-[#0f172a] border border-slate-200/90 dark:border-slate-800 flex items-center space-x-3 shadow-xs">
        <div class="w-8 h-8 rounded-lg bg-rose-50 dark:bg-rose-950/60 border border-rose-200 dark:border-rose-800 flex items-center justify-center text-rose-600 dark:text-rose-400 flex-shrink-0">
            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
            </svg>
        </div>
        <div class="min-w-0 flex-1">
            <div class="flex items-center justify-between">
                <span class="text-xs font-bold text-slate-900 dark:text-white">Fail2Ban Auto-Jail</span>
                <span class="px-1.5 py-0.2 rounded text-[9px] font-bold bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-400">ACTIVE</span>
            </div>
            <p class="text-[10px] text-slate-500 dark:text-slate-400 truncate">Automated exponential rate quarantine</p>
        </div>
    </div>

    <!-- Shield 3: Session Intelligence Sentinel -->
    <div class="p-3 rounded-xl bg-white dark:bg-[#0f172a] border border-slate-200/90 dark:border-slate-800 flex items-center space-x-3 shadow-xs">
        <div class="w-8 h-8 rounded-lg bg-cyan-50 dark:bg-cyan-950/60 border border-cyan-200 dark:border-cyan-800 flex items-center justify-center text-cyan-600 dark:text-cyan-400 flex-shrink-0">
            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M10.5 1.5H8.25A2.25 2.25 0 006 3.75v16.5a2.25 2.25 0 002.25 2.25h7.5A2.25 2.25 0 0018 20.25V3.75a2.25 2.25 0 00-2.25-2.25H13.5m-3 0V3h3V1.5m-3 0h3m-3 18.75h3" />
            </svg>
        </div>
        <div class="min-w-0 flex-1">
            <div class="flex items-center justify-between">
                <span class="text-xs font-bold text-slate-900 dark:text-white">Session Hijack Guard</span>
                <span class="px-1.5 py-0.2 rounded text-[9px] font-bold bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-400">ACTIVE</span>
            </div>
            <p class="text-[10px] text-slate-500 dark:text-slate-400 truncate">Device & IP fingerprint drift detection</p>
        </div>
    </div>

    <!-- Shield 4: Database Audit Sentinel -->
    <div class="p-3 rounded-xl bg-white dark:bg-[#0f172a] border border-slate-200/90 dark:border-slate-800 flex items-center space-x-3 shadow-xs">
        <div class="w-8 h-8 rounded-lg bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200 dark:border-emerald-800 flex items-center justify-center text-emerald-600 dark:text-emerald-400 flex-shrink-0">
            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M20.25 6.375c0 2.278-3.694 4.125-8.25 4.125S3.75 8.653 3.75 6.375m16.5 0c0-2.278-3.694-4.125-8.25-4.125S3.75 4.097 3.75 6.375m16.5 0v11.25c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125V6.375m16.5 5.625c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125" />
            </svg>
        </div>
        <div class="min-w-0 flex-1">
            <div class="flex items-center justify-between">
                <span class="text-xs font-bold text-slate-900 dark:text-white">Data Audit Sentinel</span>
                <span class="px-1.5 py-0.2 rounded text-[9px] font-bold bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-400">ACTIVE</span>
            </div>
            <p class="text-[10px] text-slate-500 dark:text-slate-400 truncate">Defanged mutation & burp audit trails</p>
        </div>
    </div>
</div>
