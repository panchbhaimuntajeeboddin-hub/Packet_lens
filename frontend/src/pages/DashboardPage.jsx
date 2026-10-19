import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Activity,
  Layers,
  UploadCloud,
  FileText,
  Download,
  Trash2,
  FolderOpen,
  Radio,
  LogOut,
  Shield,
  Clock,
  HardDrive,
  AlertTriangle,
  ExternalLink,
  Plus,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { getDashboardStats, deleteAnalysis, getExportCsvUrl } from '../services/api';
import UploadModal from '../components/UploadModal';

export default function DashboardPage() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const [stats, setStats] = useState({
    total_uploads: 0,
    total_packets: 0,
    total_bytes: 0,
    total_duration_seconds: 0,
    recent_uploads: [],
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [isUploadOpen, setIsUploadOpen] = useState(false);
  const [deleteCandidate, setDeleteCandidate] = useState(null);
  const [isDeleting, setIsDeleting] = useState(false);

  // Load private dashboard metrics from backend
  const loadDashboardData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await getDashboardStats();
      setStats(data);
    } catch (err) {
      console.error('Failed to load dashboard:', err);
      setError(err.message || 'Could not fetch your dashboard analytics.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadDashboardData();
  }, [loadDashboardData]);

  // Handle successful upload: navigate to the new analysis
  const handleUploadSuccess = (result) => {
    setIsUploadOpen(false);
    navigate(`/analysis/${result.analysis_id}`);
  };

  // Confirm and delete capture
  const handleConfirmDelete = async () => {
    if (!deleteCandidate) return;
    setIsDeleting(true);
    try {
      await deleteAnalysis(deleteCandidate.analysis_id);
      setDeleteCandidate(null);
      await loadDashboardData();
    } catch (err) {
      alert(`Delete failed: ${err.message}`);
    } finally {
      setIsDeleting(false);
    }
  };

  const handleExportCsv = (analysisId) => {
    const url = getExportCsvUrl(analysisId);
    window.open(url, '_blank');
  };

  return (
    <div className="min-h-screen bg-navy-950 text-slate-100 flex flex-col">
      {/* Top Header Bar */}
      <header className="h-16 bg-navy-900/90 backdrop-blur-md border-b border-slate-800/80 fixed top-0 inset-x-0 z-30 flex items-center justify-between px-6">
        {/* Brand */}
        <div className="flex items-center space-x-3">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-cyan-600 via-cyber-blue to-cyan-400 p-0.5 shadow-glow-cyan flex items-center justify-center">
            <div className="w-full h-full bg-navy-950 rounded-[10px] flex items-center justify-center">
              <Radio className="w-4 h-4 text-cyan-400 animate-pulse" />
            </div>
          </div>
          <div>
            <div className="flex items-center space-x-1.5">
              <span className="font-bold text-base tracking-wider text-white">PacketLens</span>
              <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-cyan-950 text-cyan-400 border border-cyan-800/40">
                SECURE CONSOLE
              </span>
            </div>
          </div>
        </div>

        {/* User Identity & Actions */}
        <div className="flex items-center space-x-4">
          <div className="text-right hidden sm:block">
            <span className="text-xs font-semibold text-white block">{user?.full_name}</span>
            <span className="text-[11px] font-mono text-cyan-400/90 block">{user?.email}</span>
          </div>

          <button
            onClick={() => setIsUploadOpen(true)}
            className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-gradient-to-r from-cyan-500 to-cyber-blue hover:from-cyan-400 hover:to-cyber-blue text-navy-950 shadow-glow-cyan transition-all transform hover:-translate-y-0.5 cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5 stroke-[2.5]" />
            <span>Upload PCAP</span>
          </button>

          <button
            onClick={logout}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800/80 hover:bg-rose-950/60 text-slate-300 hover:text-rose-300 border border-slate-700/60 hover:border-rose-800/60 transition-all cursor-pointer"
            title="Sign out of PacketLens"
          >
            <LogOut className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Sign Out</span>
          </button>
        </div>
      </header>

      {/* Main Container */}
      <main className="flex-1 pt-24 pb-12 px-6 max-w-7xl w-full mx-auto space-y-8">
        {/* Welcome Banner */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-4 border-b border-slate-800/80 gap-3">
          <div>
            <h1 className="text-2xl font-bold text-white tracking-wide flex items-center space-x-2">
              <span>Welcome back, {user?.full_name?.split(' ')[0] || 'Analyst'}</span>
            </h1>
            <p className="text-xs text-slate-400 mt-1 font-mono">
              Your private cybersecurity repository. All captures, metrics, and packets belong exclusively to your account.
            </p>
          </div>
        </div>

        {/* Metrics Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Card 1: Total Uploads */}
          <div className="bg-navy-900/60 border border-slate-800 rounded-xl p-4 shadow-sm relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono uppercase tracking-wider text-slate-400">Total Captures</span>
              <div className="p-2 rounded-lg bg-cyan-950/80 text-cyan-400 border border-cyan-800/40">
                <FolderOpen className="w-4 h-4" />
              </div>
            </div>
            <div className="mt-3">
              <span className="text-2xl font-bold font-mono text-white">
                {stats.total_uploads.toLocaleString()}
              </span>
              <span className="text-[11px] text-slate-400 block mt-0.5">Private PCAP/PCAPNG files</span>
            </div>
          </div>

          {/* Card 2: Total Packets Analyzed */}
          <div className="bg-navy-900/60 border border-slate-800 rounded-xl p-4 shadow-sm relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono uppercase tracking-wider text-slate-400">Total Packets</span>
              <div className="p-2 rounded-lg bg-emerald-950/80 text-emerald-400 border border-emerald-800/40">
                <Layers className="w-4 h-4" />
              </div>
            </div>
            <div className="mt-3">
              <span className="text-2xl font-bold font-mono text-white">
                {stats.total_packets.toLocaleString()}
              </span>
              <span className="text-[11px] text-slate-400 block mt-0.5">Dissected network frames</span>
            </div>
          </div>

          {/* Card 3: Total Traffic Volume */}
          <div className="bg-navy-900/60 border border-slate-800 rounded-xl p-4 shadow-sm relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono uppercase tracking-wider text-slate-400">Captured Volume</span>
              <div className="p-2 rounded-lg bg-purple-950/80 text-purple-400 border border-purple-800/40">
                <HardDrive className="w-4 h-4" />
              </div>
            </div>
            <div className="mt-3">
              <span className="text-2xl font-bold font-mono text-white">
                {stats.total_bytes > 1024 * 1024
                  ? `${(stats.total_bytes / (1024 * 1024)).toFixed(2)} MB`
                  : `${(stats.total_bytes / 1024).toFixed(1)} KB`}
              </span>
              <span className="text-[11px] text-slate-400 block mt-0.5">Analyzed packet data</span>
            </div>
          </div>

          {/* Card 4: Capture Duration */}
          <div className="bg-navy-900/60 border border-slate-800 rounded-xl p-4 shadow-sm relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono uppercase tracking-wider text-slate-400">Total Duration</span>
              <div className="p-2 rounded-lg bg-blue-950/80 text-blue-400 border border-blue-800/40">
                <Clock className="w-4 h-4" />
              </div>
            </div>
            <div className="mt-3">
              <span className="text-2xl font-bold font-mono text-white">
                {stats.total_duration_seconds > 60
                  ? `${(stats.total_duration_seconds / 60).toFixed(1)} min`
                  : `${stats.total_duration_seconds.toFixed(1)}s`}
              </span>
              <span className="text-[11px] text-slate-400 block mt-0.5">Cumulative capture time</span>
            </div>
          </div>
        </div>

        {/* Captures Section */}
        <div className="bg-navy-900/60 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <FolderOpen className="w-5 h-5 text-cyan-400" />
              <h2 className="text-base font-semibold text-white">Your PCAP Analysis History</h2>
            </div>
            <span className="text-xs font-mono text-slate-400">
              {stats.recent_uploads.length} recorded captures
            </span>
          </div>

          {/* Captures List or Clean Empty State */}
          {stats.recent_uploads && stats.recent_uploads.length > 0 ? (
            <div className="divide-y divide-slate-800/80">
              {stats.recent_uploads.map((session) => (
                <div
                  key={session.analysis_id}
                  className="py-4 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-slate-900/40 px-3 rounded-xl transition-colors"
                >
                  {/* File Info */}
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <span className="font-mono text-sm font-semibold text-white">
                        {session.filename}
                      </span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-950 text-cyan-400 border border-cyan-800/50">
                        {session.file_format}
                      </span>
                    </div>
                    <div className="flex items-center space-x-3 text-xs text-slate-400 font-mono">
                      <span>ID: {session.analysis_id.slice(0, 8)}...</span>
                      <span>•</span>
                      <span>{new Date(session.created_at).toLocaleString()}</span>
                      <span>•</span>
                      <span>{session.duration_seconds.toFixed(1)}s duration</span>
                    </div>
                  </div>

                  {/* Actions & Metrics */}
                  <div className="flex items-center space-x-4 self-end md:self-auto">
                    <div className="text-right font-mono text-xs hidden sm:block">
                      <span className="text-cyan-400 font-bold block">
                        {session.total_packets.toLocaleString()} packets
                      </span>
                      <span className="text-slate-400 text-[11px] block">
                        {(session.file_size_bytes / 1024).toFixed(1)} KB
                      </span>
                    </div>

                    <div className="flex items-center space-x-2">
                      {/* View Analysis */}
                      <button
                        onClick={() => navigate(`/analysis/${session.analysis_id}`)}
                        className="flex items-center space-x-1 px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-500/15 text-cyan-300 hover:bg-cyan-500/25 border border-cyan-500/30 transition-all cursor-pointer"
                        title="Open interactive packet inspector"
                      >
                        <ExternalLink className="w-3.5 h-3.5" />
                        <span>View Analysis</span>
                      </button>

                      {/* Download CSV Report */}
                      <button
                        onClick={() => handleExportCsv(session.analysis_id)}
                        className="flex items-center space-x-1 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700/60 transition-all cursor-pointer"
                        title="Download CSV report"
                      >
                        <Download className="w-3.5 h-3.5 text-cyan-400" />
                        <span>CSV</span>
                      </button>

                      {/* Delete Capture Action */}
                      <button
                        onClick={() => setDeleteCandidate(session)}
                        className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-rose-950/40 border border-transparent hover:border-rose-900/50 transition-all cursor-pointer"
                        title="Delete this capture"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            /* Clean Empty State Required for Newly Registered Users */
            <div className="py-16 text-center space-y-4 max-w-md mx-auto">
              <div className="w-16 h-16 rounded-2xl bg-cyan-950/60 border border-cyan-800/40 flex items-center justify-center mx-auto text-cyan-400">
                <FolderOpen className="w-8 h-8 opacity-70" />
              </div>
              <div>
                <h3 className="text-base font-semibold text-white">No packet captures yet</h3>
                <p className="text-xs text-slate-400 mt-1">
                  Upload your first PCAP file to begin dissecting packet layers and analyzing network flows.
                </p>
              </div>
              <button
                onClick={() => setIsUploadOpen(true)}
                className="inline-flex items-center space-x-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-cyber-blue hover:from-cyan-400 hover:to-cyber-blue text-navy-950 font-bold text-xs shadow-glow-cyan transition-all transform hover:-translate-y-0.5 cursor-pointer"
              >
                <UploadCloud className="w-4 h-4 stroke-[2.5]" />
                <span>Upload First PCAP File</span>
              </button>
            </div>
          )}
        </div>
      </main>

      {/* Delete Confirmation Modal */}
      {deleteCandidate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-navy-900 border border-rose-900/80 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-4 animate-scaleUp">
            <div className="flex items-center space-x-3 text-rose-400">
              <div className="p-2 rounded-xl bg-rose-950/80 border border-rose-800/80">
                <AlertTriangle className="w-5 h-5 text-rose-400" />
              </div>
              <h3 className="text-base font-bold text-white">Delete Capture File?</h3>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              Are you sure you want to permanently delete{' '}
              <span className="font-mono font-semibold text-rose-300">{deleteCandidate.filename}</span>?
              All computed protocol statistics and parsed packet logs will be permanently wiped.
            </p>

            <div className="flex items-center justify-end space-x-3 pt-3">
              <button
                onClick={() => setDeleteCandidate(null)}
                disabled={isDeleting}
                className="px-4 py-2 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmDelete}
                disabled={isDeleting}
                className="px-4 py-2 rounded-lg text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white shadow-lg transition-colors cursor-pointer disabled:opacity-50"
              >
                {isDeleting ? 'Deleting...' : 'Confirm Delete'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Upload Modal */}
      <UploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onUploadSuccess={handleUploadSuccess}
      />
    </div>
  );
}
