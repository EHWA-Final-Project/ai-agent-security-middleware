import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// GitHub Pages serves project sites from /<repository>/, while local preview stays at /.
const isPagesBuild = process.env.GITHUB_PAGES === 'true'

export default defineConfig({
  plugins: [react()],
  base: isPagesBuild ? '/ai-agent-security-middleware/' : '/',
  server: { host: '127.0.0.1', port: 5173, strictPort: true },
})
