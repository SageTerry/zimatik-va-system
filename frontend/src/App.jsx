import { NavLink, Route, Routes } from 'react-router-dom'
import Dashboard from './components/Dashboard'
import FindingDetail from './components/FindingDetail'
import FindingsList from './components/FindingsList'
import SettingsPage from './components/SettingsPage'

function NavItem({ to, children }) {
  return (
    <NavLink
      to={to}
      end={to === '/'}
      className={({ isActive }) =>
        `rounded-md px-3 py-2 text-sm font-medium transition ${
          isActive ? 'bg-gray-800 text-white' : 'text-gray-400 hover:bg-gray-800/60 hover:text-gray-200'
        }`
      }
    >
      {children}
    </NavLink>
  )
}

function App() {
  return (
    <div className="min-h-screen bg-gray-900 text-white">
      <header className="border-b border-gray-800 bg-gray-950/60">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-2">
            <span className="flex h-8 w-8 items-center justify-center rounded-md bg-blue-600 text-sm font-bold text-white">
              V
            </span>
            <div>
              <p className="text-sm font-bold leading-none text-white">VACE</p>
              <p className="text-xs leading-none text-gray-500">
                Vulnerability Assessment Consolidation Engine
              </p>
            </div>
          </div>
          <nav className="flex items-center gap-1">
            <NavItem to="/">Dashboard</NavItem>
            <NavItem to="/findings">Findings</NavItem>
            <NavItem to="/settings">Settings</NavItem>
          </nav>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-6 py-8">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/findings" element={<FindingsList />} />
          <Route path="/findings/:id" element={<FindingDetail />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Routes>
      </main>
    </div>
  )
}

export default App