import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// GitHub Pages project URLs require a subpath; localhost uses the root path.
export default defineConfig(({ mode }) => ({
  plugins: [react()],
  base: mode === 'pages' ? '/ai-agent-security-middleware/' : '/',
  server: { host: '127.0.0.1', port: 5173, strictPort: true },
}))
