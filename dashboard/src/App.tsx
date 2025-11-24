import { Routes, Route } from 'react-router-dom'
import { Layout } from '@/components'
import {
  Dashboard,
  Users,
  Organizations,
  Roles,
  Permissions,
  Features,
  Sessions,
  Audit,
  Settings,
} from '@/pages'

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/users" element={<Users />} />
        <Route path="/users/:id" element={<Users />} />
        <Route path="/organizations" element={<Organizations />} />
        <Route path="/organizations/:id" element={<Organizations />} />
        <Route path="/roles" element={<Roles />} />
        <Route path="/roles/:id" element={<Roles />} />
        <Route path="/permissions" element={<Permissions />} />
        <Route path="/features" element={<Features />} />
        <Route path="/features/:id" element={<Features />} />
        <Route path="/sessions" element={<Sessions />} />
        <Route path="/audit" element={<Audit />} />
        <Route path="/settings" element={<Settings />} />
      </Routes>
    </Layout>
  )
}

export default App
