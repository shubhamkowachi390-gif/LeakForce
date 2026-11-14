/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{html,js}"],
  theme: {
    extend: {
      colors: {
        base: "#101012",
        panel: "#18181b",
        panel2: "#141416",
        accent: "#22c55e",
        accent2: "#3b82f6",
        slate: {
          50: "#fafafa",
          100: "#f4f4f5",
          200: "#e4e4e7",
          300: "#d4d4d8",
          400: "#a1a1aa",
          500: "#71717a",
          600: "#52525b",
          700: "#3f3f46",
          800: "#27272a",
          900: "#18181b",
          950: "#09090b",
        },
      },
      fontFamily: {
        mono: ["Cascadia Mono", "Consolas", "ui-monospace", "monospace"],
      },
      boxShadow: {
        glow: "0 0 30px rgba(34, 197, 94, 0.16)",
      },
    },
  },
  plugins: [],
};
