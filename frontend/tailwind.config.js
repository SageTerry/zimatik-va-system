/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,jsx}",
    ],
    theme: {
        extend: {
            colors: {
                paper: '#ece8df',
                surface: '#fbf9f3',
                sunken: '#e8e5dd',
                ink: '#2b2925',
                'ink-2': '#6b6459',
                'ink-3': '#8d8571',
                'ink-4': '#a39d8f',
                line: '#c9c1ae',
                'line-strong': '#8d8571',
                'line-dashed': '#a39d8f',
                severity: {
                    critical: '#c0442f',
                    high: '#c2192b',
                    medium: '#d8842a',
                    low: '#7d746a',
                    resolved: '#5c8a4e',
                    info: '#4b7a8a',
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
                display: ['Kalam', 'cursive'],
                body: ['Patrick Hand', 'cursive'],
            },
            fontSize: {
                display: ['2.25rem', { lineHeight: '1.15' }],
                heading: ['1.5rem', { lineHeight: '1.25' }],
                stat: ['2.5rem', { lineHeight: '1' }],
                label: ['0.8125rem', { lineHeight: '1.4', letterSpacing: '0.02em' }],
            },
        },
    },
    plugins: [],
}
