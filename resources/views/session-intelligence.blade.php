@extends('security-defense::layouts.app')

@section('title', 'Session Intelligence & Client Defense')

@section('content')
    <!-- Alerts & Diagnostic Feedback -->
    @include('security-defense::components.alert-banner')

    <!-- Metric KPI Cards Row -->
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        @include('security-defense::components.stat-card', [
            'title' => 'Session Threats',
            'value' => number_format($stats['total_session_threats']),
            'subtitle' => 'Client & Post-Auth SIEM',
            'badge' => 'Sessions',
            'badgeColor' => 'zinc',
        ])

        @include('security-defense::components.stat-card', [
            'title' => 'Hijack Suspicions',
            'value' => number_format($stats['hijacks_detected']),
            'subtitle' => $stats['hijacks_detected'] > 0 ? 'Cookie theft / Subnet drift' : 'Zero hijacks detected',
            'badge' => 'Zero-Trust',
            'badgeColor' => $stats['hijacks_detected'] > 0 ? 'rose' : 'emerald',
        ])

        @include('security-defense::components.stat-card', [
            'title' => 'Velocity Anomalies',
            'value' => number_format($stats['velocity_spikes']),
            'subtitle' => 'Post-login scraping bots',
            'badge' => 'Behavioral',
            'badgeColor' => $stats['velocity_spikes'] > 0 ? 'orange' : 'zinc',
        ])

        @include('security-defense::components.stat-card', [
            'title' => 'Header Anomalies',
            'value' => number_format($stats['header_anomalies']),
            'subtitle' => 'Contradictory client UA/headers',
            'badge' => 'Client',
            'badgeColor' => $stats['header_anomalies'] > 0 ? 'orange' : 'zinc',
        ])
    </div>

    <!-- Date Range Filter -->
    <div class="flex items-center justify-between gap-3 mb-3">
        @include('security-defense::components.date-range-filter', ['current' => $dateRange['preset']])
    </div>

    <!-- Session Filter Bar Component -->
    @include('security-defense::components.sessions.session-filter-bar', ['filters' => $filters])

    <!-- Threats Table Component -->
    @include('security-defense::components.sessions.session-threats-table', ['alerts' => $alerts])
@endsection
