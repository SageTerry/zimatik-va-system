/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,jsx}",
    ],
    theme: {
        extend: {
            colors: {
                // Page/surface neutrals - light, airy dashboard background.
                paper: '#F1F3F6',
                surface: '#FFFFFF',
                sunken: '#F5F7FA',
                ink: '#0B1F3A',
                'ink-2': '#54607A',
                'ink-3': '#8993A6',
                'ink-4': '#B7BFCB',
                line: '#E5E8EE',
                'line-strong': '#D3D8E1',
                'line-dashed': '#D3D8E1',
                // Brand palette (navy / blue / red / light gray).
                navy: {
                    DEFAULT: '#0B1F5C',
                    dark: '#081647',
                    light: '#1A3B8C',
                },
                brand: {
                    DEFAULT: '#1857A4',
                    dark: '#12417F',
                    light: '#EAF1FB',
                },
                accent: {
                    DEFAULT: '#D91C1C',
                    dark: '#B01414',
                    light: '#FCEBEB',
                },
                severity: {
                    critical: '#B91424',
                    high: '#D91C1C',
                    medium: '#D97706',
                    low: '#64748B',
                    resolved: '#15803D',
                    info: '#1857A4',
                },
            },
            spacing: {
                1: '4px',
                2: '8px',
                3: '12px',
                4: '16px',
                5: '22px',
                6: '28px',
                8: '36px',
                10: '48px',
            },
            fontFamily: {
                display: ['"Plus Jakarta Sans"', 'sans-serif'],
                body: ['"Plus Jakarta Sans"', 'sans-serif'],
            },
            fontSize: {
                display: ['1.875rem', { lineHeight: '1.25', fontWeight: '700' }],
                heading: ['1.25rem', { lineHeight: '1.35', fontWeight: '600' }],
                stat: ['2rem', { lineHeight: '1.15', fontWeight: '700' }],
                label: ['0.75rem', { lineHeight: '1.4', letterSpacing: '0.04em' }],
            },
            boxShadow: {
                card: '0 1px 2px rgba(11, 31, 90, 0.04), 0 4px 12px rgba(11, 31, 90, 0.06)',
                'card-hover': '0 2px 4px rgba(11, 31, 90, 0.06), 0 8px 20px rgba(11, 31, 90, 0.09)',
                sidebar: '1px 0 0 rgba(11, 31, 90, 0.04)',
            },
        },
    },
    plugins: [],
}
