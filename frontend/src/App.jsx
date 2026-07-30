import { NavLink, Route, Routes } from 'react-router-dom'
import CodeScanForm from './components/CodeScanForm'
import Dashboard from './components/Dashboard'
import FindingDetail from './components/FindingDetail'
import FindingsList from './components/FindingsList'
import MobileScanForm from './components/MobileScanForm'
import ScanForm from './components/ScanForm'
import ScanProgress from './components/ScanProgress'
import ScanResults from './components/ScanResults'
import SettingsPage from './components/SettingsPage'
import { ShieldIcon } from './lib/icons'

function NavItem({ to, children }) {
  return (
    <NavLink
      to={to}
      end={to === '/'}
      className={({ isActive }) =>
        `radius-c border px-3 py-2 font-body text-base transition-colors ${
          isActive
            ? 'border-ink text-ink'
            : 'border-transparent text-ink-2 hover:border-line hover:text-ink'
        }`
      }
    >
      {children}
    </NavLink>
  )
}

function App() {
  return (
    <div className="min-h-screen bg-paper text-ink">
      <header className="border-b border-line">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-3">
            <span className="radius-b flex h-9 w-9 items-center justify-center border border-ink text-ink">
              <ShieldIcon size={20} strokeWidth={2} />
            </span>
            <div>
              <p className="font-display text-lg leading-none text-ink">VACE</p>
              <p className="font-body text-xs leading-none text-ink-3">
                Vulnerability Assessment Consolidation Engine
              </p>
            </div>
          </div>
          <nav className="flex items-center gap-1">
            <NavItem to="/">Dashboard</NavItem>
            <NavItem to="/findings">Findings</NavItem>
            <NavItem to="/scan">New Scan</NavItem>
            <NavItem to="/scan/mobile">Scan Mobile App</NavItem>
            <NavItem to="/scan/code">Scan Code</NavItem>
            <NavItem to="/settings">Settings</NavItem>
          </nav>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-6 py-8">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/findings" element={<FindingsList />} />
          <Route path="/findings/:id" element={<FindingDetail />} />
          <Route path="/scan" element={<ScanForm />} />
          <Route path="/scan/mobile" element={<MobileScanForm />} />
          <Route path="/scan/code" element={<CodeScanForm />} />
          <Route path="/scan/progress/:scanId" element={<ScanProgress />} />
          <Route path="/scan-results/:scanId" element={<ScanResults />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Routes>
      </main>
    </div>
  )
}

export default App
