@extends('security-defense::layouts.app')

@section('title', 'Security Defense Monitoring')

@section('content')
    <!-- Alerts & Diagnostic Feedback Toasts / Banners -->
    @include('security-defense::components.alert-banner')

    <!-- Metric KPI Cards Row -->
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        @include('security-defense::components.stat-card', [
            'title' => 'Total Threats',
            'value' => number_format($stats['total']),
            'subtitle' => 'Recorded in SIEM DB',
            'badge' => 'Database',
            'badgeColor' => 'zinc',
        ])

        @include('security-defense::components.stat-card', [
            'title' => 'Pending Triage',
            'value' => number_format($stats['new']),
            'subtitle' => $stats['new'] > 0 ? 'Requires attention' : 'Clean stream',
            'badge' => 'Active',
            'badgeColor' => $stats['new'] > 0 ? 'rose' : 'emerald',
        ])

        @include('security-defense::components.stat-card', [
            'title' => 'Critical / High',
            'value' => number_format($stats['critical']) . ' / ' . number_format($stats['high']),
            'subtitle' => 'High severity vectors',
            'badge' => 'Severe',
            'badgeColor' => ($stats['critical'] + $stats['high']) > 0 ? 'orange' : 'zinc',
        ])

        @include('security-defense::components.stat-card', [
            'title' => 'Quarantined IPs',
            'value' => count($quarantinedIps),
            'subtitle' => 'Active Fail2Ban Jails',
            'badge' => 'Firewall',
            'badgeColor' => count($quarantinedIps) > 0 ? 'rose' : 'zinc',
        ])
    </div>

    <!-- Epistemic Summary -->
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5 mt-3.5">
        @include('security-defense::components.stat-card', [
            'title' => 'Epistemic Engine',
            'value' => $epistemicSummary['enabled'] ? 'Enabled' : 'Disabled',
            'subtitle' => 'Probabilistic assessment',
            'badge' => 'Epistemic',
            'badgeColor' => $epistemicSummary['enabled'] ? 'emerald' : 'zinc',
        ])
        @include('security-defense::components.stat-card', [
            'title' => 'Learned Patterns',
            'value' => number_format($epistemicSummary['patterns']),
            'subtitle' => 'Memory index entries',
            'badge' => 'Memory',
            'badgeColor' => 'violet',
        ])
        @include('security-defense::components.stat-card', [
            'title' => 'Last Analysis Risk',
            'value' => $epistemicSummary['risk'] === null ? '—' : number_format($epistemicSummary['risk'] * 100, 1) . '%',
            'subtitle' => 'Cached assessment',
            'badge' => 'Risk',
            'badgeColor' => $epistemicSummary['risk'] !== null && $epistemicSummary['risk'] >= 0.7 ? 'rose' : 'zinc',
        ])
    </div>

    <!-- Date Range Filter -->
    <div class="flex items-center justify-between gap-3 mb-3">
        @include('security-defense::components.date-range-filter', ['current' => $dateRange['preset']])
    </div>

    <!-- Quick Actions Toggles -->
    @include('security-defense::components.quick-actions', [
        'blockHeadless' => $quickActions['blockHeadless'],
        'cspArmor' => $quickActions['cspArmor'],
        'asyncQueue' => $quickActions['asyncQueue'],
    ])

    <!-- Threat Velocity Timeline & Attack Vector Analytics Charts -->
    @include('security-defense::components.threat-analytics-charts', [
        'hourlyData' => $hourlyData,
        'threatDistribution' => $threatDistribution,
        'postureScore' => $postureScore,
    ])

    <!-- Compact Notification Channels & Webhook Testing Hub -->
    @include('security-defense::components.channels-hub', [
        'channelsStatus' => $channelsStatus,
    ])

    <!-- Live WAF Blocked Events Meter -->
    @include('security-defense::components.live-events-table', [
        'events' => $liveEvents,
    ])

    <!-- Active IP Quarantine Management Table -->
    @include('security-defense::components.quarantine-table', [
        'quarantinedIps' => $quarantinedIps,
    ])

    <!-- Recent Alerts and Telemetry Table -->
    @include('security-defense::components.alerts-table', [
        'alerts' => $alerts,
        'filters' => $filters,
    ])

    <!-- Telemetry Inspector Modal -->
    @include('security-defense::components.telemetry-modal')
@endsection
