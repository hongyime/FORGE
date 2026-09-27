import { defineConfig } from 'vite'
import { env } from 'node:process'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    watch: { usePolling: env.CHOKIDAR_USEPOLLING === 'true' },
    proxy: {
      '/api': env.DEV_API_URL || 'http://localhost:8080',
      '/ws': { target: env.DEV_API_URL || 'ws://localhost:8080', ws: true },
    },
  },
})
