@extends('security-defense::layouts.app')

@section('title', 'Epistemic Defense')

@section('content')
    @php
        $epistemicStats = $stats ?? [];
        $hypotheses = $hypotheses ?? [];
        $evidenceFeed = $evidenceFeed ?? [];
        $responseAdapters = $responseAdapters ?? [];
        $epistemicConfig = $epistemicConfig ?? config('security-defense.epistemic', []);
        $feedbackRoute = $feedbackRoute ?? url()->current();
        $allHypothesisValues = [
            'account_compromise', 'credential_stuffing', 'session_hijack', 'brute_force_attack',
            'data_exfiltration', 'insider_threat', 'automated_scraping', 'impossible_travel',
            'payload_attack', 'bot_activity', 'compound_attack', 'unknown',
        ];
    @endphp

    {{-- Header --}}
    <div class="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
            <p class="text-xs font-semibold uppercase tracking-[0.18em] text-[#E8734A]">Epistemic engine</p>
            <h1 class="mt-1 text-2xl font-bold tracking-tight text-zinc-950 dark:text-zinc-100">Threat reasoning dashboard</h1>
            <p class="mt-1 text-sm text-zinc-500 dark:text-zinc-400">Beliefs, evidence, policy decisions, and response readiness.</p>
        </div>
        <span class="inline-flex w-fit items-center gap-2 rounded-full border border-zinc-300 bg-white px-3 py-1.5 text-xs font-medium text-zinc-600 shadow-sm dark:border-zinc-800 dark:bg-[#121214] dark:text-zinc-300">
            <span class="h-2 w-2 rounded-full {{ ($epistemicConfig['enabled'] ?? false) ? 'bg-emerald-500' : 'bg-zinc-400' }}"></span>
            {{ ($epistemicConfig['enabled'] ?? false) ? 'Engine enabled' : 'Engine disabled' }}
        </span>
    </div>

    {{-- Summary Cards --}}
    <div class="grid grid-cols-1 gap-3.5 sm:grid-cols-2 lg:grid-cols-5">
        @include('security-defense::components.stat-card', [
            'title' => 'Total analyses',
            'value' => number_format($epistemicStats['total_analyses'] ?? 0),
            'subtitle' => 'Assessment runs',
            'badge' => 'Engine',
            'badgeColor' => 'orange',
        ])
        @include('security-defense::components.stat-card', [
            'title' => 'Average risk',
            'value' => number_format((float) ($epistemicStats['average_risk'] ?? 0), 2),
            'subtitle' => 'Score 0-1',
            'badge' => 'Risk',
            'badgeColor' => 'rose',
        ])
        @include('security-defense::components.stat-card', [
            'title' => 'Average confidence',
            'value' => number_format((float) ($epistemicStats['average_confidence'] ?? 0), 2),
            'subtitle' => 'Belief strength',
            'badge' => 'Belief',
            'badgeColor' => 'purple',
        ])
        @include('security-defense::components.stat-card', [
            'title' => 'Feedback count',
            'value' => number_format($epistemicStats['feedback_count'] ?? 0),
            'subtitle' => 'Verified outcomes',
            'badge' => 'Labels',
            'badgeColor' => 'emerald',
        ])
        @include('security-defense::components.stat-card', [
            'title' => 'Memory patterns',
            'value' => number_format($epistemicStats['memory_patterns'] ?? 0),
            'subtitle' => 'Retained patterns',
            'badge' => 'Memory',
            'badgeColor' => 'amber',
        ])
    </div>

    {{-- Hypotheses Table + Evidence Feed --}}
    <div class="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <section class="overflow-hidden rounded-xl border border-zinc-300/80 bg-white shadow-sm dark:border-zinc-800 dark:bg-[#121214] xl:col-span-2">
            <div class="flex items-center justify-between border-b border-zinc-200 px-4 py-4 dark:border-zinc-800 sm:px-5">
                <div>
                    <h2 class="text-sm font-bold text-zinc-900 dark:text-zinc-100">Latest threat hypotheses</h2>
                    <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">Current belief state and policy action.</p>
                </div>
                <svg class="h-5 w-5 text-[#E8734A]" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75 11.25 15 15 9.75M12 3.75 4.5 7.5v4.5c0 4.8 3.2 7.5 7.5 8.25 4.3-.75 7.5-3.45 7.5-8.25V7.5L12 3.75Z" /></svg>
            </div>
            <div class="overflow-x-auto">
                <table class="min-w-full text-left text-sm" role="table" aria-label="Threat hypotheses">
                    <thead class="bg-zinc-50 text-[10px] uppercase tracking-wider text-zinc-500 dark:bg-[#18181b] dark:text-zinc-400">
                        <tr>
                            <th class="px-4 py-3 font-semibold sm:px-5" scope="col">Hypothesis</th>
                            <th class="px-4 py-3 font-semibold" scope="col">Confidence</th>
                            <th class="px-4 py-3 font-semibold" scope="col">Evidence</th>
                            <th class="px-4 py-3 font-semibold" scope="col">Risk</th>
                            <th class="px-4 py-3 font-semibold" scope="col">Policy</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-zinc-200 dark:divide-zinc-800">
                        @forelse($hypotheses as $belief)
                            @php
                                $hypothesis = $belief['hypothesis'] ?? 'Unknown';
                                $confidence = (float) ($belief['confidence'] ?? 0);
                                $risk = (float) ($belief['risk'] ?? 0);
                                $supporting = $belief['supporting'] ?? [];
                                $contradicting = $belief['contradicting'] ?? [];
                                $action = $belief['action'] ?? 'monitor';
                            @endphp
                            <tr class="align-middle hover:bg-zinc-50 dark:hover:bg-zinc-900/60">
                                <td class="whitespace-nowrap px-4 py-3 font-medium text-zinc-900 dark:text-zinc-100 sm:px-5">
                                    {{ $hypothesis }}
                                </td>
                                <td class="min-w-36 px-4 py-3">
                                    <div class="flex items-center gap-2">
                                        <div class="h-1.5 w-20 overflow-hidden rounded-full bg-zinc-200 dark:bg-zinc-700" role="progressbar" aria-valuenow="{{ max(0, min(100, (int) ($confidence * 100))) }}" aria-valuemin="0" aria-valuemax="100" aria-label="Confidence level">
                                            <div class="h-full rounded-full bg-[#E8734A]" style="width: {{ max(0, min(100, $confidence * 100)) }}%"></div>
                                        </div>
                                        <span class="font-mono text-xs text-zinc-600 dark:text-zinc-300">{{ number_format($confidence, 2) }}</span>
                                    </div>
                                </td>
                                <td class="whitespace-nowrap px-4 py-3 text-xs text-zinc-600 dark:text-zinc-400">
                                    <span class="text-emerald-600 dark:text-emerald-400">{{ count($supporting) }} supporting</span>
                                    <span class="mx-1 text-zinc-300 dark:text-zinc-700">/</span>
                                    <span class="text-rose-600 dark:text-rose-400">{{ count($contradicting) }} contradicting</span>
                                </td>
                                <td class="whitespace-nowrap px-4 py-3 font-mono text-xs text-zinc-700 dark:text-zinc-300">
                                    {{ number_format($risk, 2) }}
                                </td>
                                <td class="whitespace-nowrap px-4 py-3">
                                    <span class="rounded-md border border-zinc-300 px-2 py-1 text-[10px] font-bold uppercase text-zinc-700 dark:border-zinc-700 dark:text-zinc-300">{{ $action }}</span>
                                </td>
                            </tr>
                        @empty
                            <tr>
                                <td colspan="5" class="px-5 py-8 text-center text-sm text-zinc-500 dark:text-zinc-400">No threat hypotheses available.</td>
                            </tr>
                        @endforelse
                    </tbody>
                </table>
            </div>
        </section>

        <section class="rounded-xl border border-zinc-300/80 bg-white shadow-sm dark:border-zinc-800 dark:bg-[#121214]">
            <div class="border-b border-zinc-200 px-4 py-4 dark:border-zinc-800 sm:px-5">
                <h2 class="text-sm font-bold text-zinc-900 dark:text-zinc-100">Evidence feed</h2>
                <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">Recent signals used by analysis.</p>
            </div>
            <div class="divide-y divide-zinc-200 dark:divide-zinc-800">
                @forelse($evidenceFeed as $evidence)
                    <div class="px-4 py-3 sm:px-5">
                        <div class="flex items-start justify-between gap-3">
                            <span class="text-xs font-semibold text-zinc-900 dark:text-zinc-100">{{ $evidence['type'] ?? 'signal' }}</span>
                            <span class="font-mono text-[10px] text-zinc-500 dark:text-zinc-400">{{ $evidence['timestamp'] ?? '---' }}</span>
                        </div>
                        <div class="mt-1 flex items-center justify-between gap-2 text-xs text-zinc-500 dark:text-zinc-400">
                            <span class="truncate">{{ $evidence['source'] ?? 'Unknown source' }}</span>
                            <span class="shrink-0 font-mono">{{ number_format((float) ($evidence['reliability'] ?? 0), 2) }}</span>
                        </div>
                    </div>
                @empty
                    <p class="px-5 py-8 text-center text-sm text-zinc-500 dark:text-zinc-400">No evidence received.</p>
                @endforelse
            </div>
        </section>
    </div>

    {{-- Response Adapter Status + Config --}}
    <div class="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <section class="rounded-xl border border-zinc-300/80 bg-white shadow-sm dark:border-zinc-800 dark:bg-[#121214] lg:col-span-2">
            <div class="border-b border-zinc-200 px-4 py-4 dark:border-zinc-800 sm:px-5">
                <h2 class="text-sm font-bold text-zinc-900 dark:text-zinc-100">Response adapter status</h2>
            </div>
            <div class="overflow-x-auto">
                <table class="min-w-full text-left text-sm" role="table" aria-label="Response adapters">
                    <thead class="bg-zinc-50 text-[10px] uppercase tracking-wider text-zinc-500 dark:bg-[#18181b] dark:text-zinc-400">
                        <tr>
                            <th class="px-4 py-3 font-semibold sm:px-5" scope="col">Adapter class</th>
                            <th class="px-4 py-3 font-semibold" scope="col">Status</th>
                            <th class="px-4 py-3 font-semibold" scope="col">Last response</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-zinc-200 dark:divide-zinc-800">
                        @forelse($responseAdapters as $adapter)
                            @php
                                $adapterClass = $adapter['class'] ?? 'Unknown';
                                $adapterEnabled = $adapter['enabled'] ?? false;
                                $lastResponse = $adapter['last_response'] ?? 'No response recorded';
                            @endphp
                            <tr>
                                <td class="px-4 py-3 font-mono text-xs text-zinc-700 dark:text-zinc-300 sm:px-5">{{ $adapterClass }}</td>
                                <td class="px-4 py-3">
                                    <span class="inline-flex items-center gap-1.5 text-xs font-semibold {{ $adapterEnabled ? 'text-emerald-600 dark:text-emerald-400' : 'text-zinc-500 dark:text-zinc-400' }}">
                                        <span class="h-1.5 w-1.5 rounded-full bg-current"></span>
                                        {{ $adapterEnabled ? 'Enabled' : 'Disabled' }}
                                    </span>
                                </td>
                                <td class="px-4 py-3 text-xs text-zinc-600 dark:text-zinc-400">{{ $lastResponse }}</td>
                            </tr>
                        @empty
                            <tr>
                                <td colspan="3" class="px-5 py-8 text-center text-sm text-zinc-500 dark:text-zinc-400">No adapters configured.</td>
                            </tr>
                        @endforelse
                    </tbody>
                </table>
            </div>
        </section>

        <section class="rounded-xl border border-zinc-300/80 bg-white shadow-sm dark:border-zinc-800 dark:bg-[#121214]">
            <div class="border-b border-zinc-200 px-4 py-4 dark:border-zinc-800 sm:px-5">
                <h2 class="text-sm font-bold text-zinc-900 dark:text-zinc-100">Config status</h2>
            </div>
            <dl class="divide-y divide-zinc-200 dark:divide-zinc-800" aria-label="Configuration values">
                @php
                    $configRows = [
                        ['Epistemic enabled', $epistemicConfig['enabled'] ?? false],
                        ['Response enabled', $epistemicConfig['response']['enabled'] ?? false],
                        ['AI max evidence', $epistemicConfig['ai']['max_evidence'] ?? 0],
                        ['Graph nodes / depth', ($epistemicConfig['graph']['max_nodes'] ?? 0) . ' nodes / ' . ($epistemicConfig['graph']['max_depth'] ?? 0) . ' depth'],
                        ['Memory retention', ($epistemicConfig['memory']['retention_days'] ?? 0) . ' days'],
                    ];
                @endphp
                @foreach($configRows as $configRow)
                    <div class="flex items-center justify-between gap-3 px-4 py-3 text-xs sm:px-5">
                        <dt class="text-zinc-500 dark:text-zinc-400">{{ $configRow[0] }}</dt>
                        <dd class="font-mono font-semibold text-zinc-800 dark:text-zinc-200">
                            {{ is_bool($configRow[1]) ? ($configRow[1] ? 'Enabled' : 'Disabled') : $configRow[1] }}
                        </dd>
                    </div>
                @endforeach
            </dl>
        </section>
    </div>

    {{-- Feedback Form --}}
    <section class="rounded-xl border border-zinc-300/80 bg-white shadow-sm dark:border-zinc-800 dark:bg-[#121214]">
        <div class="flex items-center gap-3 border-b border-zinc-200 px-4 py-4 dark:border-zinc-800 sm:px-5">
            <svg class="h-5 w-5 text-[#E8734A]" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8" aria-hidden="true">
                <path stroke-linecap="round" stroke-linejoin="round" d="M7.5 12h9m-9 3h6m-9.75 5.25h15A2.25 2.25 0 0 0 21 18V6a2.25 2.25 0 0 0-2.25-2.25h-13.5A2.25 2.25 0 0 0 3 6v12a2.25 2.25 0 0 0 2.25 2.25Z" />
            </svg>
            <div>
                <h2 class="text-sm font-bold text-zinc-900 dark:text-zinc-100">Record feedback</h2>
                <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">Label prior hypothesis outcome to improve memory patterns.</p>
            </div>
        </div>
        <form method="POST" action="{{ $feedbackRoute }}" class="grid grid-cols-1 gap-4 p-4 sm:grid-cols-3 sm:items-end sm:p-5">
            @csrf
            <label class="block">
                <span class="mb-1.5 block text-xs font-semibold text-zinc-600 dark:text-zinc-300">Hypothesis</span>
                <select name="hypothesis" required class="w-full rounded-lg border border-zinc-300 bg-white px-3 py-2.5 text-sm text-zinc-900 outline-none focus:border-[#E8734A] dark:border-zinc-700 dark:bg-[#18181b] dark:text-zinc-100">
                    <option value="">Select hypothesis</option>
                    @foreach($allHypothesisValues as $hyp)
                        <option value="{{ $hyp }}">{{ str_replace('_', ' ', ucfirst($hyp)) }}</option>
                    @endforeach
                </select>
            </label>
            <label class="block">
                <span class="mb-1.5 block text-xs font-semibold text-zinc-600 dark:text-zinc-300">Outcome</span>
                <select name="outcome" required class="w-full rounded-lg border border-zinc-300 bg-white px-3 py-2.5 text-sm text-zinc-900 outline-none focus:border-[#E8734A] dark:border-zinc-700 dark:bg-[#18181b] dark:text-zinc-100">
                    <option value="confirmed_attack">Confirmed attack</option>
                    <option value="false_positive">False positive</option>
                </select>
            </label>
            <button type="submit" class="rounded-lg bg-[#E8734A] px-4 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-[#d5673e] focus:outline-none focus:ring-2 focus:ring-[#E8734A] focus:ring-offset-2 transition">
                Submit feedback
            </button>
        </form>
    </section>
@endsection
