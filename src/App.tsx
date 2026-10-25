import { lazy, Suspense } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { Shell } from './components/Shell';
import { Landing } from './pages/Landing';
import { DashboardPage } from './pages/DashboardPage';
import { IngestPage } from './pages/IngestPage';
import { OverviewPage } from './pages/OverviewPage';
import { FindingsPage } from './pages/FindingsPage';
import { IncidentsPage } from './pages/IncidentsPage';
import { FlowsPage } from './pages/FlowsPage';
import { GraphPage } from './pages/GraphPage';
import { TimelinePage } from './pages/TimelinePage';
import { AssistantPage } from './pages/AssistantPage';
import { NotesPage } from './pages/NotesPage';
import { ReportsPage } from './pages/ReportsPage';
import { SettingsPage } from './pages/SettingsPage';
import { DiagnosticsPage } from './pages/DiagnosticsPage';

const DiffPage = lazy(() => import('./pages/DiffPage'));
const LabPage = lazy(() => import('./pages/LabPage'));

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/app" element={<Shell />}>
        <Route index element={<Navigate to="dashboard" replace />} />
        <Route path="dashboard" element={<DashboardPage />} />
        <Route path="ingest" element={<IngestPage />} />
        <Route path="overview" element={<OverviewPage />} />
        <Route path="findings" element={<FindingsPage />} />
        <Route path="incidents" element={<IncidentsPage />} />
        <Route path="flows" element={<FlowsPage />} />
        <Route path="graph" element={<GraphPage />} />
        <Route path="timeline" element={<TimelinePage />} />
        <Route path="assistant" element={<AssistantPage />} />
        <Route path="diff" element={<Suspense fallback={null}><DiffPage /></Suspense>} />
        <Route path="notes" element={<NotesPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="lab" element={<Suspense fallback={null}><LabPage /></Suspense>} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="diagnostics" element={<DiagnosticsPage />} />
        <Route path="*" element={<Navigate to="dashboard" replace />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
