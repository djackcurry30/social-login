import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'node:path'

// https://vitejs.dev/config/
//
// 设计依据：订单处理（§A.2）：
//   - base: '/admin/' 与后端 MountAdmin 一致：所有静态资源挂在 /admin/ 下
//   - dev server 跨域：浏览器从 5173 访问 8080 时要带 cookie，必须显式 CORS
//   - build.outDir: 'dist' 配合后端 go:embed all:dist
//   - sourcemap: true 方便生产错误栈能定位到原始 .tsx
export default defineConfig({
  plugins: [react()],
  base: '/admin/',
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      // 把 /admin/v1/* 转到后端 8080；其它路径由 vite 自己处理
      '/admin/v1': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: true,
  },
})