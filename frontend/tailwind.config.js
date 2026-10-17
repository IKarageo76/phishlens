/** @type {import('tailwindcss').Config} */
const v = (name) => `rgb(var(--${name}) / <alpha-value>)`;
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: ["class"],
  theme: {
    extend: {
      colors: {
        base: v("base"),
        panel: v("panel"),
        sunk: v("sunk"),
        line: v("line"),
        ink: v("ink"),
        muted: v("muted"),
        lens: v("lens"),
        bad: v("bad"),
        warn: v("warn"),
        good: v("good"),
      },
      fontFamily: {
        sans: ['"Schibsted Grotesk Variable"', "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono Variable"', "ui-monospace", "monospace"],
      },
      borderRadius: { sm: "4px", DEFAULT: "6px", lg: "10px" },
    },
  },
  plugins: [],
};
