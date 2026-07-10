import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Relative base so the built SPA can be served from any path (reverse-proxy or
// an optional axum static route). See architecture spec §7 (deploy).
export default defineConfig({
  base: "./",
  plugins: [react()],
  server: { port: 5180, host: true },
  preview: { port: 5180 },
  build: { outDir: "dist", sourcemap: false, target: "es2022" },
});
