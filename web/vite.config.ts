import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  base: '/console/',
  plugins: [react()],
  define: { __BUILD_ID__: JSON.stringify(process.env.DRAFRP_BUILD_ID || 'development') },
  server: {
    proxy: {
      '/api': { target: process.env.DRAFRP_DEV_PROXY || 'http://127.0.0.1:8080', changeOrigin: true },
      '/auth': { target: process.env.DRAFRP_DEV_PROXY || 'http://127.0.0.1:8080', changeOrigin: true },
    },
  },
});
