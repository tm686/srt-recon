import { useEffect, useState } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AppShell } from "@/components/layout/AppShell";
import { ProjectsPage } from "@/pages/ProjectsPage";
import { ProjectDetailPage } from "@/pages/ProjectDetailPage";
import { SettingsPage } from "@/pages/SettingsPage";
import { ActiveScanPage } from "@/pages/ActiveScanPage";
import { ResultsPage } from "@/pages/ResultsPage";
import { SetupPage } from "@/pages/SetupPage";
import { UnlockPage } from "@/pages/UnlockPage";
import api from "@/lib/api";
import type { SetupStatus } from "@/types/settings";

function App() {
  const [status, setStatus] = useState<SetupStatus | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .get<SetupStatus>("/setup/status")
      .then(({ data }) => setStatus(data))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center text-text-muted">
        Loading...
      </div>
    );
  }

  const needsSetup = !status?.setup_complete;
  const needsUnlock = status?.setup_complete && !status.vault_unlocked;

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/setup" element={<SetupPage />} />
        <Route path="/unlock" element={<UnlockPage />} />

        {needsSetup ? (
          <Route path="*" element={<Navigate to="/setup" replace />} />
        ) : needsUnlock ? (
          <Route path="*" element={<Navigate to="/unlock" replace />} />
        ) : (
          <Route element={<AppShell />}>
            <Route path="/projects" element={<ProjectsPage />} />
            <Route path="/projects/:id" element={<ProjectDetailPage />} />
            <Route path="/scan" element={<ActiveScanPage />} />
            <Route path="/results" element={<ResultsPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/projects" replace />} />
          </Route>
        )}
      </Routes>
    </BrowserRouter>
  );
}

export default App;
