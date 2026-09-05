@extends('security-defense::layouts.app')

@section('title', 'Database Mutation & Tamper Monitoring')

@section('content')
    <!-- Alerts & Diagnostic Feedback -->
    @include('security-defense::components.alert-banner')

    <!-- Metric KPI Cards Row -->
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        @include('security-defense::components.stat-card', [
            'title' => 'Total Mutations',
            'value' => number_format($stats['total']),
            'subtitle' => 'Recorded in Audit Trail',
            'badge' => 'Database',
            'badgeColor' => 'zinc',
        ])

        @include('security-defense::components.stat-card', [
            'title' => 'Tamper Detected',
            'value' => number_format($stats['tampered']),
            'subtitle' => $stats['tampered'] > 0 ? 'Burp Suite / Mass Assignment' : 'Zero tampering detected',
            'badge' => 'Integrity',
            'badgeColor' => $stats['tampered'] > 0 ? 'rose' : 'emerald',
        ])

        @include('security-defense::components.stat-card', [
            'title' => 'Today\'s Mutations',
            'value' => number_format($stats['today']),
            'subtitle' => 'Captured in last 24h',
            'badge' => 'Live',
            'badgeColor' => 'cyan',
        ])

        @include('security-defense::components.stat-card', [
            'title' => 'Distinct Actors',
            'value' => number_format($stats['unique_actors']),
            'subtitle' => 'Authenticated Users / Admins',
            'badge' => 'Actors',
            'badgeColor' => 'zinc',
        ])
    </div>

    <!-- Date Range Filter -->
    <div class="flex items-center justify-between gap-3 mb-3">
        @include('security-defense::components.date-range-filter', ['current' => $dateRange['preset']])
    </div>

    <!-- Filter Bar Component -->
    @include('security-defense::components.audits.audit-filter-bar', ['filters' => $filters])

    <!-- Mutations Table Component -->
    @include('security-defense::components.audits.audit-table', ['audits' => $audits])

    <!-- Interactive Diff & Payload Modal Component -->
    @include('security-defense::components.audits.audit-diff-modal')
@endsection
