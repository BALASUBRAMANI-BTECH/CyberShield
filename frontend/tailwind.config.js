/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          950: '#060B13',
          900: '#0B1320',
          850: '#0F1A2C',
          800: '#142238',
          700: '#1E3250',
          600: '#2A4670',
          500: '#3D6299',
          accent: '#06B6D4', // cyan-500
          neon: '#00F0FF',
          blue: '#3B82F6',
          violet: '#8B5CF6',
          critical: '#EF4444',
          high: '#F97316',
          medium: '#F59E0B',
          low: '#3B82F6',
          info: '#10B981',
          fixed: '#10B981',
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
      },
      boxShadow: {
        'glow-cyan': '0 0 15px -3px rgba(6, 182, 212, 0.35)',
        'glow-blue': '0 0 15px -3px rgba(59, 130, 246, 0.35)',
        'glow-red': '0 0 15px -3px rgba(239, 68, 68, 0.35)',
      }
    },
  },
  plugins: [],
}
