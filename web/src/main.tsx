// src/main.tsx — 入口。
//
// 设计依据：架构 §15.6 "管理端 SPA + 单 binary embed"。
// 路由：BrowserRouter；base = /admin/（与 vite.config.ts base 对齐）。
//       子路由用相对路径，方便"挂载在不同前缀"场景复用。

import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'

import App from './App'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter basename="/admin">
      <App />
    </BrowserRouter>
  </React.StrictMode>,
)