import { Navigate, NavLink, Outlet, Route, Routes, useNavigate } from 'react-router-dom'
import CodeScanForm from './components/CodeScanForm'
import Dashboard from './components/Dashboard'
import FindingDetail from './components/FindingDetail'
import FindingsList from './components/FindingsList'
import LoginPage from './components/LoginPage'
import MobileScanForm from './components/MobileScanForm'
import ReportsPage from './components/ReportsPage'
import ScanForm from './components/ScanForm'
import ScanProgress from './components/ScanProgress'
import ScanResults from './components/ScanResults'
import SettingsPage from './components/SettingsPage'
import {
  CodeIcon,
  GearIcon,
  GridIcon,
  ListIcon,
  LogoutIcon,
  ScanIcon,
  ShieldIcon,
  SmartphoneIcon,
} from './lib/icons'

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', icon: GridIcon, end: true },
  { to: '/findings', label: 'Findings', icon: ListIcon },
  { to: '/scan', label: 'New Scan', icon: ScanIcon },
  { to: '/scan/mobile', label: 'Scan Mobile App', icon: SmartphoneIcon },
  { to: '/scan/code', label: 'Scan Code', icon: CodeIcon },
]

function NavItem({ to, end, icon: Icon, children }) {
  return (
    <NavLink
      to={to}
      end={end}
      className={({ isActive }) =>
        `radius-b flex items-center gap-3 px-3.5 py-2.5 font-body text-sm font-medium transition-colors ${
          isActive
            ? 'bg-brand-light text-brand'
            : 'text-ink-2 hover:bg-sunken hover:text-ink'
        }`
      }
    >
      <Icon size={19} strokeWidth={2} />
      {children}
    </NavLink>
  )
}

// Redirects to /login if there's no stored token, otherwise renders the
// wrapped route. The axios response interceptor (api/client.js) handles the
// complementary case - a token that exists but has expired/been rejected
// mid-session.
function ProtectedRoute({ children }) {
  if (!localStorage.getItem('access_token')) {
    return <Navigate to="/login" replace />
  }
  return children
}

// Shared sidebar + content shell for every authenticated route.
function AppLayout() {
  const navigate = useNavigate()

  function handleLogout() {
    localStorage.removeItem('access_token')
    navigate('/login')
  }

  return (
    <div className="flex min-h-screen bg-paper text-ink">
      <aside className="flex w-64 shrink-0 flex-col border-r border-line bg-surface px-4 py-6">
        <div className="flex items-center gap-3 px-2 pb-6">
          <span className="radius-b flex h-10 w-10 items-center justify-center bg-navy text-white">
            <ShieldIcon size={20} strokeWidth={2} />
          </span>
          <div>
            <p className="font-display text-base leading-none text-ink">VACE</p>
            <p className="mt-1 font-body text-xs leading-none text-ink-3">Security Console</p>
          </div>
        </div>

        <nav className="flex flex-1 flex-col gap-1">
          {NAV_ITEMS.map((item) => (
            <NavItem key={item.to} to={item.to} end={item.end} icon={item.icon}>
              {item.label}
            </NavItem>
          ))}
        </nav>

        <div className="flex flex-col gap-1 border-t border-line pt-3">
          <NavItem to="/settings" icon={GearIcon}>
            Settings
          </NavItem>
          <button
            type="button"
            onClick={handleLogout}
            className="radius-b flex cursor-pointer items-center gap-3 px-3.5 py-2.5 font-body text-sm font-medium text-ink-2 transition-colors hover:bg-accent-light hover:text-accent"
          >
            <LogoutIcon size={19} strokeWidth={2} />
            Logout
          </button>
        </div>
      </aside>

      <main className="min-w-0 flex-1 overflow-y-auto px-8 py-8">
        <Outlet />
      </main>
    </div>
  )
}

function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<AppLayout />}>
        <Route
          path="/"
          element={
            <ProtectedRoute>
              <Dashboard />
            </ProtectedRoute>
          }
        />
        <Route
          path="/findings"
          element={
            <ProtectedRoute>
              <FindingsList />
            </ProtectedRoute>
          }
        />
        <Route
          path="/findings/:id"
          element={
            <ProtectedRoute>
              <FindingDetail />
            </ProtectedRoute>
          }
        />
        <Route
          path="/scan"
          element={
            <ProtectedRoute>
              <ScanForm />
            </ProtectedRoute>
          }
        />
        <Route
          path="/scan/mobile"
          element={
            <ProtectedRoute>
              <MobileScanForm />
            </ProtectedRoute>
          }
        />
        <Route
          path="/scan/code"
          element={
            <ProtectedRoute>
              <CodeScanForm />
            </ProtectedRoute>
          }
        />
        <Route
          path="/scan/progress/:scanId"
          element={
            <ProtectedRoute>
              <ScanProgress />
            </ProtectedRoute>
          }
        />
        <Route
          path="/scan-results/:scanId"
          element={
            <ProtectedRoute>
              <ScanResults />
            </ProtectedRoute>
          }
        />
        <Route
          path="/reports/:scan_id"
          element={
            <ProtectedRoute>
              <ReportsPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="/settings"
          element={
            <ProtectedRoute>
              <SettingsPage />
            </ProtectedRoute>
          }
        />
      </Route>
    </Routes>
  )
}

export default App
