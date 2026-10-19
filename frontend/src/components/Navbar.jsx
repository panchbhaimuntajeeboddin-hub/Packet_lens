import React from 'react';
import { Download, RefreshCw, FileText, Upload, Shield } from 'lucide-react';
import { getExportCsvUrl } from '../services/api';

export default function Navbar({ currentSession, onOpenUpload, onRefresh }) {
  const handleExportCsv = () => {
    if (!currentSession?.analysis_id) return;
    const downloadUrl = getExportCsvUrl(currentSession.analysis_id);
    window.open(downloadUrl, '_blank');
  };

  return (
    <header className="h-16 bg-navy-900/80 backdrop-blur-md border-b border-slate-800/80 fixed top-0 right-0 left-64 z-20 flex items-center justify-between px-6">
      {/* Session Header / Title */}
      <div className="flex items-center space-x-4">
        <div>
          <h1 className="text-base font-semibold text-white flex items-center space-x-2">
            <span>{currentSession ? currentSession.filename : 'Network Traffic Analysis Dashboard'}</span>
            {currentSession && (
              <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-cyan-950/80 text-cyan-400 border border-cyan-800/40">
                {currentSession.file_format}
              </span>
            )}
          </h1>
          <p className="text-xs text-slate-400 font-mono">
            {currentSession
              ? `Session ID: ${currentSession.analysis_id.slice(0, 8)}... | Captured: ${new Date(currentSession.created_at).toLocaleString()}`
              : 'Dissecting packets, extracting protocols, and computing endpoint analytics'}
          </p>
        </div>
      </div>

      {/* Action Buttons */}
      <div className="flex items-center space-x-3">
        {currentSession && (
          <button
            onClick={handleExportCsv}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700/60 hover:border-cyan-500/40 transition-all cursor-pointer shadow-sm"
            title="Download analyzed packets as CSV"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export CSV</span>
          </button>
        )}

        <button
          onClick={onOpenUpload}
          className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-cyan-500/15 text-cyan-300 hover:bg-cyan-500/25 border border-cyan-500/30 transition-all cursor-pointer"
        >
          <Upload className="w-3.5 h-3.5" />
          <span>Upload PCAP</span>
        </button>
      </div>
    </header>
  );
}
