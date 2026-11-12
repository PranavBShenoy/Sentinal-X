import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from '../features/auth/AuthContext';
import { Layout } from '../components/Layout';
import { LoginPage } from '../features/auth/LoginPage';
import { RegisterPage } from '../features/auth/RegisterPage';
import { DashboardPage } from '../features/dashboard/DashboardPage';
import { ProjectsPage } from '../features/projects/ProjectsPage';
import { NewAssessmentPage } from '../features/assessments/NewAssessmentPage';
import { AssessmentDetailPage } from '../features/assessments/AssessmentDetailPage';
import { FindingsPage } from '../features/findings/FindingsPage';
import { DependencyGraphView } from '../features/findings/DependencyGraphView';
import { RemediationPage } from '../features/remediation/RemediationPage';
import { ReportsPage } from '../features/reports/ReportsPage';

const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center text-slate-400 text-sm">
        Authenticating session...
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          {/* Public Routes */}
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />

          {/* Protected Application Routes */}
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <Layout />
              </ProtectedRoute>
            }
          >
            <Route index element={<DashboardPage />} />
            <Route path="projects" element={<ProjectsPage />} />
            <Route path="assessments/new" element={<NewAssessmentPage />} />
            <Route path="assessments/:id" element={<AssessmentDetailPage />} />
            <Route path="assessments/:id/graph" element={<DependencyGraphView />} />
            <Route path="findings" element={<FindingsPage />} />
            <Route path="remediation" element={<RemediationPage />} />
            <Route path="reports" element={<ReportsPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
};
