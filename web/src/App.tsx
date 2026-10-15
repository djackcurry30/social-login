// src/App.tsx — 路由表。

import { Routes, Route, Navigate } from 'react-router-dom'

import Layout from '@/components/Layout'
import RequireAuth from '@/components/RequireAuth'
import LoginPage from '@/pages/LoginPage'
import AppsPage from '@/pages/AppsPage'
import AppNewPage from '@/pages/AppNewPage'
import AppDetailPage from '@/pages/AppDetailPage'
import ChannelsPage from '@/pages/ChannelsPage'
import ObservabilityPage from '@/pages/ObservabilityPage'

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />

      <Route
        element={
          <RequireAuth>
            <Layout />
          </RequireAuth>
        }
      >
        <Route index element={<Navigate to="/apps" replace />} />
        <Route path="/apps" element={<AppsPage />} />
        <Route path="/apps/new" element={<AppNewPage />} />
        <Route path="/apps/:id" element={<AppDetailPage />} />
        <Route path="/channels" element={<ChannelsPage />} />
        <Route path="/observability" element={<ObservabilityPage />} />
      </Route>

      <Route path="*" element={<Navigate to="/apps" replace />} />
    </Routes>
  )
}