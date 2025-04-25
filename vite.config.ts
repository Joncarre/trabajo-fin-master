import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react' // Use the installed plugin

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // Proxy /api requests to the backend server
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true, // Recommended for virtual hosted sites
        // secure: false, // Uncomment if backend is not HTTPS
        // rewrite: (path) => path.replace(/^\/api/, '') // Uncomment if backend doesn't expect /api prefix
      }
    }
  }
})
