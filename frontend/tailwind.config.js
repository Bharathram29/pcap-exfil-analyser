/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        soc: {
          bg: "#070b14",
          panel: "#0f172a",
          card: "#111c33",
          border: "#1e293b",
          accent: "#38bdf8",
        },
      },
    },
  },
  plugins: [],
};
