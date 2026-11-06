import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  base: "/console/",
  plugins: [react()],
  define: {
    __BUILD_ID__: JSON.stringify(process.env.DRAFRP_BUILD_ID || "development"),
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes("node_modules")) return;
          if (/node_modules\/(react|react-dom|scheduler)\//.test(id))
            return "react";
          if (/node_modules\/(@mui|@emotion|@popperjs|stylis)\//.test(id))
            return "material";
          if (/node_modules\/(zod|react-hook-form)\//.test(id)) return "forms";
          return "vendor";
        },
      },
    },
  },
  server: {
    proxy: {
      "/api": {
        target: process.env.DRAFRP_DEV_PROXY || "http://127.0.0.1:8080",
        // Keep the browser Host aligned with Origin for the cloud's CSRF checks.
        changeOrigin: false,
      },
      "/auth": {
        target: process.env.DRAFRP_DEV_PROXY || "http://127.0.0.1:8080",
        changeOrigin: false,
      },
    },
  },
});
