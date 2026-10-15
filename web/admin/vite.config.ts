import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  // dist/.gitkeep stays so go:embed compiles without a UI build.
  build: { outDir: 'dist/app', emptyOutDir: true },
  // Same origin as admin in development too, so the session cookie and
  // cross-origin protection behave as in production.
  server: { proxy: { '/api': 'http://localhost:8081' } },
});
