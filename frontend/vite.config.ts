/// <reference types="vitest" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// В dev-режиме запросы /api/* проксируются на FastAPI (по умолчанию localhost:8000),
// поэтому браузер видит один origin и CORS не нужен.
// VITE_BASE — путь, под которым живёт SPA («/» отдельно, «/vm/» в «Платформе»);
// VITE_API_BASE — префикс API («/api» отдельно, «/api/vm» в «Платформе»).
const apiTarget = process.env.VM_API_URL ?? "http://localhost:8000";

export default defineConfig({
  base: process.env.VITE_BASE ?? "/",
  plugins: [react()],
  server: {
    port: 5174,
    proxy: {
      "/api": {
        target: apiTarget,
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
  build: { outDir: "dist", sourcemap: false },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: false,
  },
});
