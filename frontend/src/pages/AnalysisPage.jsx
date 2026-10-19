import React, { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import {
  ArrowLeft,
  Download,
  UploadCloud,
  Layers,
  Radio,
  AlertTriangle,
  FolderOpen,
  Activity,
  Shield,
} from 'lucide-react';

import StatsCards from '../components/StatsCards';
import ProtocolChart from '../components/ProtocolChart';
import TrafficTimelineChart from '../components/TrafficTimelineChart';
import FlowsView from '../components/FlowsView';
import PacketTable from '../components/PacketTable';
import PacketDetailsModal from '../components/PacketDetailsModal';
import UploadModal from '../components/UploadModal';

import {
  getAnalysisSession,
  getAnalysisPackets,
  getExportCsvUrl,
} from '../services/api';

export default function AnalysisPage() {
  const { analysisId } = useParams();
  const navigate = useNavigate();

  const [session, setSession] = useState(null);
  const [statistics, setStatistics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [activeTab, setActiveTab] = useState('overview'); // 'overview' | 'packets'
  const [packets, setPackets] = useState([]);
  const [totalMatched, setTotalMatched] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [totalPages, setTotalPages] = useState(1);
  const [filters, setFilters] = useState({
    protocol: '',
    ip: '',
    port: '',
    search: '',
  });

  const [selectedPacket, setSelectedPacket] = useState(null);
  const [isUploadOpen, setIsUploadOpen] = useState(false);
  const [isLoadingPackets, setIsLoadingPackets] = useState(false);

  // Fetch session metadata and statistics
  const loadSessionData = useCallback(async () => {
    if (!analysisId) return;
    setLoading(true);
    setError(null);
    try {
      const data = await getAnalysisSession(analysisId);
      setSession(data);
      setStatistics(data.statistics);
    } catch (err) {
      console.error('Failed to load session:', err);
      setError(err.message || 'Capture session not found or access denied.');
    } finally {
      setLoading(false);
    }
  }, [analysisId]);

  useEffect(() => {
    loadSessionData();
  }, [loadSessionData]);

  // Fetch packets whenever page, pageSize, or filters change
  const fetchPackets = useCallback(async () => {
    if (!analysisId || !session) return;
    setIsLoadingPackets(true);
    try {
      const data = await getAnalysisPackets(analysisId, {
        page,
        pageSize,
        protocol: filters.protocol,
        ip: filters.ip,
        port: filters.port,
        search: filters.search,
      });
      setPackets(data.packets || []);
      setTotalMatched(data.total_matched || 0);
      setTotalPages(data.total_pages || 1);
    } catch (err) {
      console.error('Failed to load packets:', err);
      setPackets([]);
    } finally {
      setIsLoadingPackets(false);
    }
  }, [analysisId, session, page, pageSize, filters]);

  useEffect(() => {
    fetchPackets();
  }, [fetchPackets]);

  const handleExportCsv = () => {
    if (!analysisId) return;
    const url = getExportCsvUrl(analysisId);
    window.open(url, '_blank');
  };

  const handleSelectProtocol = (protocolName) => {
    setFilters((prev) => ({ ...prev, protocol: protocolName }));
    setActiveTab('packets');
  };

  const handleSelectIp = (ipAddress) => {
    setFilters((prev) => ({ ...prev, ip: ipAddress }));
    setActiveTab('packets');
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-navy-950 flex flex-col items-center justify-center space-y-4">
        <div className="w-12 h-12 rounded-xl bg-gradient-to-tr from-cyan-600 to-cyber-blue p-0.5 shadow-glow-cyan flex items-center justify-center animate-pulse">
          <div className="w-full h-full bg-navy-950 rounded-[10px] flex items-center justify-center">
            <Radio className="w-6 h-6 text-cyan-400 animate-spin" />
          </div>
        </div>
        <p className="text-xs font-mono text-cyan-400 tracking-wider">
          DISSECTING CAPTURE SESSION...
        </p>
      </div>
    );
  }

  if (error || !session) {
    return (
      <div className="min-h-screen bg-navy-950 text-slate-100 flex flex-col items-center justify-center px-4">
        <div className="max-w-md w-full bg-navy-900 border border-slate-800 rounded-2xl p-8 text-center space-y-4 shadow-2xl">
          <div className="w-12 h-12 rounded-xl bg-rose-950/80 border border-rose-800/80 mx-auto flex items-center justify-center text-rose-400">
            <AlertTriangle className="w-6 h-6" />
          </div>
          <h2 className="text-lg font-bold text-white">Capture Inaccessible</h2>
          <p className="text-xs text-slate-400 leading-relaxed font-mono">
            {error || 'This capture session either does not exist or belongs to another analyst.'}
          </p>
          <div className="pt-2">
            <Link
              to="/dashboard"
              className="inline-flex items-center space-x-2 px-4 py-2 rounded-xl bg-cyan-500/20 text-cyan-300 hover:bg-cyan-500/30 border border-cyan-500/30 text-xs font-semibold transition-all"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>Return to My Dashboard</span>
            </Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-navy-950 text-slate-100 flex flex-col">
      {/* Top Navbar */}
      <header className="h-16 bg-navy-900/90 backdrop-blur-md border-b border-slate-800/80 fixed top-0 inset-x-0 z-30 flex items-center justify-between px-6">
        <div className="flex items-center space-x-4">
          <Link
            to="/dashboard"
            className="flex items-center space-x-1 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800/80 hover:bg-slate-700 text-slate-300 border border-slate-700/60 transition-colors"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Dashboard</span>
          </Link>

          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-sm font-semibold text-white font-mono truncate max-w-xs sm:max-w-md" title={session.filename}>
                {session.filename}
              </h1>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-950 text-cyan-400 border border-cyan-800/40">
                {session.file_format}
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-mono hidden sm:block">
              Analyzed {new Date(session.created_at).toLocaleString()} • {session.total_packets.toLocaleString()} packets
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center space-x-3">
          {/* View Toggle Tabs */}
          <div className="flex items-center bg-navy-950/80 p-0.5 rounded-lg border border-slate-800 text-xs font-medium font-mono">
            <button
              onClick={() => setActiveTab('overview')}
              className={`px-3 py-1 rounded-md transition-all cursor-pointer ${
                activeTab === 'overview'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Overview & Analytics
            </button>
            <button
              onClick={() => setActiveTab('packets')}
              className={`px-3 py-1 rounded-md transition-all cursor-pointer ${
                activeTab === 'packets'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Packet Matrix
            </button>
          </div>

          <button
            onClick={handleExportCsv}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700/60 hover:border-cyan-500/40 transition-all cursor-pointer"
            title="Download CSV packet dump"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span className="hidden sm:inline">Export CSV</span>
          </button>

          <button
            onClick={() => setIsUploadOpen(true)}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-500/15 text-cyan-300 hover:bg-cyan-500/25 border border-cyan-500/30 transition-all cursor-pointer"
          >
            <UploadCloud className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">New PCAP</span>
          </button>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 pt-24 pb-12 px-6 max-w-7xl w-full mx-auto space-y-6">
        {/* Executive Cards */}
        {statistics && <StatsCards statistics={statistics} />}

        {/* Tab 1: Overview */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Top Charts Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <ProtocolChart
                statistics={statistics}
                onSelectProtocol={handleSelectProtocol}
              />
              <TrafficTimelineChart
                packets={packets}
                duration={statistics?.duration_seconds || 1}
              />
            </div>

            {/* Flows / Top Talkers */}
            <FlowsView
              statistics={statistics}
              onSelectIp={handleSelectIp}
            />

            {/* Quick Packet Inspector Preview */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <Layers className="w-4 h-4 text-cyan-400" />
                  <h2 className="text-sm font-semibold text-white">Live Dissected Packet Stream</h2>
                </div>
                <button
                  onClick={() => setActiveTab('packets')}
                  className="text-xs font-mono text-cyan-400 hover:text-cyan-300 transition-colors cursor-pointer"
                >
                  Open Full Inspector Matrix &rarr;
                </button>
              </div>

              <PacketTable
                packets={packets}
                page={page}
                pageSize={pageSize}
                totalPages={totalPages}
                totalMatched={totalMatched}
                filters={filters}
                onFilterChange={(newFilters) => {
                  setFilters(newFilters);
                  setPage(1);
                }}
                onPageChange={setPage}
                onPageSizeChange={(newSize) => {
                  setPageSize(newSize);
                  setPage(1);
                }}
                onSelectPacket={setSelectedPacket}
                isLoading={isLoadingPackets}
              />
            </div>
          </div>
        )}

        {/* Tab 2: Full Packet Inspector */}
        {activeTab === 'packets' && (
          <div className="space-y-4">
            <div>
              <h2 className="text-base font-semibold text-white flex items-center space-x-2">
                <Layers className="w-5 h-5 text-cyan-400" />
                <span>Interactive Packet Dissection & Filter Matrix</span>
              </h2>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Filter by OSI layers: L2 MAC, L3 IPv4/IPv6/ARP, L4 TCP/UDP/ICMP, L7 DNS
              </p>
            </div>

            <PacketTable
              packets={packets}
              page={page}
              pageSize={pageSize}
              totalPages={totalPages}
              totalMatched={totalMatched}
              filters={filters}
              onFilterChange={(newFilters) => {
                setFilters(newFilters);
                setPage(1);
              }}
              onPageChange={setPage}
              onPageSizeChange={(newSize) => {
                setPageSize(newSize);
                setPage(1);
              }}
              onSelectPacket={setSelectedPacket}
              isLoading={isLoadingPackets}
            />
          </div>
        )}
      </main>

      {/* Packet Deep Dissection Modal */}
      <PacketDetailsModal
        packet={selectedPacket}
        onClose={() => setSelectedPacket(null)}
      />

      {/* Upload Modal */}
      <UploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onUploadSuccess={(result) => {
          setIsUploadOpen(false);
          navigate(`/analysis/${result.analysis_id}`);
        }}
      />
    </div>
  );
}
