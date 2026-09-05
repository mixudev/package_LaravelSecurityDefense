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
            'badgeColor' => 'slate',
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
            'badgeColor' => ($stats['critical'] + $stats['high']) > 0 ? 'orange' : 'slate',
        ])

        @include('security-defense::components.stat-card', [
            'title' => 'Quarantined IPs',
            'value' => count($quarantinedIps),
            'subtitle' => 'Active Fail2Ban Jails',
            'badge' => 'Firewall',
            'badgeColor' => count($quarantinedIps) > 0 ? 'rose' : 'slate',
        ])
    </div>

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
