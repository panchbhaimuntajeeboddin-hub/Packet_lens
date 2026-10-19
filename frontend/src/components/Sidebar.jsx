import React from 'react';
import {
  Activity,
  Layers,
  Radio,
  FileText,
  UploadCloud,
  History,
  Shield,
  ExternalLink,
} from 'lucide-react';

export default function Sidebar({
  activeTab,
  setActiveTab,
  onOpenUpload,
  currentSession,
  recentSessions,
  onSelectSession,
  apiOnline,
}) {
  const navItems = [
    { id: 'dashboard', label: 'Traffic Dashboard', icon: Activity },
    { id: 'packets', label: 'Packet Inspector', icon: Layers },
    { id: 'history', label: 'Captures History', icon: History },
  ];

  return (
    <aside className="w-64 bg-navy-900 border-r border-slate-800/80 flex flex-col h-screen fixed left-0 top-0 z-30 select-none">
      {/* Brand Header */}
      <div className="p-5 border-b border-slate-800/80 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 via-cyber-blue to-cyan-400 p-0.5 shadow-glow-cyan flex items-center justify-center">
            <div className="w-full h-full bg-navy-950 rounded-[10px] flex items-center justify-center">
              <Radio className="w-5 h-5 text-cyan-400 animate-pulse" />
            </div>
          </div>
          <div>
            <div className="flex items-center space-x-1.5">
              <span className="font-bold text-lg tracking-wider bg-gradient-to-r from-white via-slate-100 to-cyan-300 bg-clip-text text-transparent">
                PacketLens
              </span>
            </div>
            <span className="text-[10px] uppercase font-mono tracking-widest text-cyan-500/80 font-medium">
              Traffic Analyzer
            </span>
          </div>
        </div>
      </div>

      {/* Upload Action Button */}
      <div className="p-4">
        <button
          onClick={onOpenUpload}
          className="w-full flex items-center justify-center space-x-2 py-2.5 px-4 rounded-lg bg-gradient-to-r from-cyan-500 to-cyber-blue hover:from-cyan-400 hover:to-cyber-blue text-navy-950 font-semibold text-sm shadow-glow-cyan transition-all transform hover:-translate-y-0.5 active:translate-y-0 cursor-pointer"
        >
          <UploadCloud className="w-4 h-4 stroke-[2.5]" />
          <span>Analyze New PCAP</span>
        </button>
      </div>

      {/* Navigation Links */}
      <div className="px-3 py-2 flex-1 space-y-1">
        <p className="px-3 text-[11px] font-semibold tracking-wider text-slate-400 uppercase font-mono mb-2">
          Navigation
        </p>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors cursor-pointer ${
                isActive
                  ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-inner'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
              <span>{item.label}</span>
            </button>
          );
        })}

        {/* Current Active Capture Info */}
        {currentSession && (
          <div className="pt-6">
            <p className="px-3 text-[11px] font-semibold tracking-wider text-slate-400 uppercase font-mono mb-2">
              Active Capture
            </p>
            <div className="mx-2 p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs">
              <div className="flex items-center justify-between mb-1">
                <span className="font-mono text-cyan-300 font-medium truncate max-w-[130px]" title={currentSession.filename}>
                  {currentSession.filename}
                </span>
                <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-cyan-950 text-cyan-400 border border-cyan-800/50">
                  {currentSession.file_format}
                </span>
              </div>
              <div className="flex justify-between text-slate-400 text-[11px]">
                <span>{currentSession.total_packets?.toLocaleString()} packets</span>
                <span>{(currentSession.file_size_bytes / 1024).toFixed(1)} KB</span>
              </div>
            </div>
          </div>
        )}

        {/* Recent Captures */}
        {recentSessions && recentSessions.length > 0 && (
          <div className="pt-4">
            <p className="px-3 text-[11px] font-semibold tracking-wider text-slate-400 uppercase font-mono mb-2">
              Recent Analyses
            </p>
            <div className="space-y-1 max-h-36 overflow-y-auto px-1">
              {recentSessions.slice(0, 4).map((s) => (
                <button
                  key={s.analysis_id}
                  onClick={() => onSelectSession(s.analysis_id)}
                  className={`w-full text-left px-2 py-1.5 rounded text-xs truncate transition-colors flex items-center justify-between ${
                    currentSession?.analysis_id === s.analysis_id
                      ? 'bg-cyan-500/15 text-cyan-300'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                  }`}
                >
                  <span className="truncate">{s.filename}</span>
                  <span className="text-[10px] text-slate-400 font-mono ml-2">
                    {s.total_packets}p
                  </span>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Footer System Status */}
      <div className="p-4 border-t border-slate-800/80 bg-slate-950/40">
        <div className="flex items-center justify-between text-xs text-slate-400">
          <div className="flex items-center space-x-2">
            <span className={`w-2 h-2 rounded-full ${apiOnline ? 'bg-emerald-400 shadow-[0_0_8px_#34D399]' : 'bg-rose-500 shadow-[0_0_8px_#F43F5E]'}`} />
            <span className="font-mono text-[11px]">
              {apiOnline ? 'FastAPI Online' : 'API Offline'}
            </span>
          </div>
          <span className="text-[10px] text-slate-400 font-mono">v0.1.0</span>
        </div>
      </div>
    </aside>
  );
}
