import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

/**
 * The dev server proxies /api to the Express API, so the browser only ever talks
 * to one origin and there is no CORS negotiation during development.
 */
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: false,
    proxy: {
      '/api': {
        target: process.env.VITE_API_TARGET || 'http://127.0.0.1:4000',
        changeOrigin: true
      }
    }
  },
  build: { outDir: 'dist', sourcemap: false, chunkSizeWarningLimit: 900 }
});
