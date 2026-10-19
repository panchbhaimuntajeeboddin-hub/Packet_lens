import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Radio } from 'lucide-react';

export function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="min-h-screen bg-navy-950 flex flex-col items-center justify-center space-y-4">
        <div className="w-12 h-12 rounded-xl bg-gradient-to-tr from-cyan-600 to-cyber-blue p-0.5 shadow-glow-cyan flex items-center justify-center animate-pulse">
          <div className="w-full h-full bg-navy-950 rounded-[10px] flex items-center justify-center">
            <Radio className="w-6 h-6 text-cyan-400 animate-spin" />
          </div>
        </div>
        <p className="text-xs font-mono text-cyan-400 tracking-wider">VERIFYING ANALYST CREDENTIALS...</p>
      </div>
    );
  }

  if (!user) {
    // Redirect to login preserving the return path
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return children;
}

export function PublicOnlyRoute({ children }) {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-navy-950 flex flex-col items-center justify-center space-y-4">
        <div className="w-12 h-12 rounded-xl bg-gradient-to-tr from-cyan-600 to-cyber-blue p-0.5 shadow-glow-cyan flex items-center justify-center animate-pulse">
          <div className="w-full h-full bg-navy-950 rounded-[10px] flex items-center justify-center">
            <Radio className="w-6 h-6 text-cyan-400" />
          </div>
        </div>
      </div>
    );
  }

  if (user) {
    return <Navigate to="/dashboard" replace />;
  }

  return children;
}
