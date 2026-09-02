/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        ink: '#12212f',
        paper: '#e9edf1',
        slate: '#5b6b7c',
        meta: '#8494a3',
        indigo: '#0a5f9e',
        navy: '#0d1e33',
        'navy-active': '#16304f',
        'navy-hover': '#183254',
        accent: '#2b8fd6',
        amber: '#a8560b',
        garnet: '#8f1d1d',
        mint: '#1f6f5c',
        rule: '#d3dae1',
        'rule-soft': '#eef1f4',
        'field-border': '#c3ccd6',
        'soft-bg': '#f6f8fa',
      },
      fontFamily: {
        title: [
          'Century Gothic',
          'URW Gothic',
          'Jost',
          'Questrial',
          'ui-sans-serif',
          'system-ui',
          'sans-serif',
        ],
        sans: [
          'Century Gothic',
          'URW Gothic',
          'Jost',
          'Questrial',
          'ui-sans-serif',
          'system-ui',
          'sans-serif',
        ],
        mono: ['IBM Plex Mono', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      borderRadius: {
        btn: '9px',
      },
    },
  },
  plugins: [],
}
