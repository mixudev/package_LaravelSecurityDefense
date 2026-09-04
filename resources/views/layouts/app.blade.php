<!DOCTYPE html>
<html lang="en" class="h-full">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>@yield('title', 'Security Defense SIEM') &bull; Local Console</title>

    <!-- Google Fonts: Inter & JetBrains Mono -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">

    <!-- Anti-Flash Dark Mode Initialization -->
    <script>
        (function() {
            try {
                const stored = localStorage.getItem('security_defense_theme');
                if (stored === 'dark' || (!stored && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
                    document.documentElement.classList.add('dark');
                } else {
                    document.documentElement.classList.remove('dark');
                }
            } catch (e) {}
        })();
    </script>

    <!-- Standalone Tailwind CSS v4 Browser Runtime (Isolated to Dashboard) -->
    <script src="https://unpkg.com/@tailwindcss/browser@4"></script>

    <!-- Configure class-based dark mode (Tailwind v4 defaults to prefers-color-scheme;
         this makes the .dark class on <html> drive all dark: variants) -->
    <style type="text/tailwindcss">
        @custom-variant dark (&:where(.dark, .dark *));
    </style>

    <style>
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }
        code, pre, .font-mono {
            font-family: 'JetBrains Mono', monospace;
        }
        /* Sharp, subtle custom scrollbar */
        ::-webkit-scrollbar {
            width: 5px;
            height: 5px;
        }
        ::-webkit-scrollbar-track {
            background: transparent;
        }
        ::-webkit-scrollbar-thumb {
            background: rgba(161, 161, 170, 0.3);
            border-radius: 2px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: rgba(161, 161, 170, 0.5);
        }
    </style>
</head>
<body class="min-h-full flex flex-col bg-zinc-50 dark:bg-zinc-950 text-zinc-900 dark:text-zinc-100 antialiased transition-colors duration-150">

    <!-- Navigation Header -->
    @include('security-defense::components.navbar')

    <!-- Main Content Container -->
    <main class="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        @yield('content')
    </main>

    <!-- Footer -->
    <footer class="border-t border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-950 py-4 mt-auto">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-2 text-xs text-zinc-500 dark:text-zinc-500">
            <div>
                Laravel Security Defense SIEM &bull; Active Anomaly Correlation Engine
            </div>
            <div class="font-mono text-[11px]">
                Environment: <span class="text-zinc-800 dark:text-zinc-300 font-semibold">{{ strtoupper(app()->environment()) }}</span>
            </div>
        </div>
    </footer>

    <!-- Theme Switcher JavaScript -->
    <script>
        function toggleTheme() {
            const isDark = document.documentElement.classList.toggle('dark');
            localStorage.setItem('security_defense_theme', isDark ? 'dark' : 'light');
            updateThemeIcon();
        }

        function updateThemeIcon() {
            const isDark = document.documentElement.classList.contains('dark');
            const sun = document.getElementById('theme-icon-sun');
            const moon = document.getElementById('theme-icon-moon');
            if (sun && moon) {
                if (isDark) {
                    sun.classList.remove('hidden');
                    moon.classList.add('hidden');
                } else {
                    sun.classList.add('hidden');
                    moon.classList.remove('hidden');
                }
            }
        }

        document.addEventListener('DOMContentLoaded', updateThemeIcon);
    </script>

    @stack('scripts')
</body>
</html>
