/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        mono: ["JetBrains Mono", "Fira Code", "Menlo", "monospace"],
      },
      colors: {
        bg: "#0b0e14",
        panel: "#121620",
        border: "#1f2533",
        muted: "#5b6478",
        accent: "#6cb6ff",
        ok: "#7ee787",
        warn: "#f0a76b",
        bad: "#ff6b6b",
      },
    },
  },
  plugins: [],
};
