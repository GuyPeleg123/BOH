import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "path";

// Two fully separate builds — one per GUI role (see AppCapture.tsx /
// AppDecrypt.tsx). `vite build --mode capture` and `--mode decrypt` each
// run an independent Rollup pass from a DIFFERENT single HTML entry
// (index.html vs decrypt.html, each with its own main-*.tsx), so the
// resulting bundle for one role never contains the other role's page code —
// not just a hidden nav, a disjoint module graph. Backend picks the output
// dir by LTESNIFFER_GUI_ROLE (see gui/backend/main.py FRONTEND_DIST).
export default defineConfig(({ mode }) => ({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        ws: true,
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: mode === "decrypt" ? "dist-decrypt" : "dist-capture",
    emptyOutDir: true,
    rollupOptions: {
      input: resolve(__dirname, mode === "decrypt" ? "decrypt.html" : "index.html"),
    },
  },
}));
