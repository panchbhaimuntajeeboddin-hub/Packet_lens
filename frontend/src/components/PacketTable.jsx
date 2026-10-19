import React from 'react';
import {
  Search,
  Filter,
  ChevronLeft,
  ChevronRight,
  RotateCcw,
  Eye,
  Layers,
  ArrowRight,
  Loader2,
} from 'lucide-react';

const PROTO_BADGES = {
  TCP: 'bg-cyan-950/80 text-cyan-300 border-cyan-800/60',
  HTTP: 'bg-sky-950/80 text-sky-300 border-sky-800/60',
  DNS: 'bg-purple-950/80 text-purple-300 border-purple-800/60',
  UDP: 'bg-emerald-950/80 text-emerald-300 border-emerald-800/60',
  ICMP: 'bg-amber-950/80 text-amber-300 border-amber-800/60',
  ARP: 'bg-rose-950/80 text-rose-300 border-rose-800/60',
  IPv6: 'bg-indigo-950/80 text-indigo-300 border-indigo-800/60',
};

const PROTOCOL_OPTIONS = ['All', 'TCP', 'UDP', 'DNS', 'HTTP', 'ICMP', 'ARP'];

export default function PacketTable({
  packets = [],
  page = 1,
  pageSize = 50,
  totalPages = 1,
  totalMatched = 0,
  filters = {},
  onFilterChange,
  onPageChange,
  onPageSizeChange,
  onSelectPacket,
  isLoading = false,
}) {
  const handleProtocolClick = (proto) => {
    onFilterChange({
      ...filters,
      protocol: proto === 'All' ? '' : proto,
    });
  };

  const handleInputChange = (field, value) => {
    onFilterChange({
      ...filters,
      [field]: value,
    });
  };

  const handleResetFilters = () => {
    onFilterChange({
      protocol: '',
      ip: '',
      port: '',
      search: '',
    });
  };

  const hasActiveFilters = Boolean(
    filters.protocol || filters.ip || filters.port || filters.search
  );

  return (
    <div className="glass-panel rounded-xl border border-slate-800 overflow-hidden flex flex-col">
      {/* Table Control Bar */}
      <div className="p-4 border-b border-slate-800 space-y-3 bg-slate-900/40">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          {/* Protocol Pills */}
          <div className="flex items-center space-x-1.5 overflow-x-auto pb-1 lg:pb-0">
            <span className="text-xs font-mono text-slate-400 mr-1 flex items-center space-x-1">
              <Filter className="w-3 h-3 text-cyan-400" />
              <span>Filter:</span>
            </span>
            {PROTOCOL_OPTIONS.map((proto) => {
              const isSelected =
                (proto === 'All' && !filters.protocol) ||
                filters.protocol === proto;
              return (
                <button
                  key={proto}
                  onClick={() => handleProtocolClick(proto)}
                  className={`px-2.5 py-1 rounded text-xs font-mono transition-all cursor-pointer ${
                    isSelected
                      ? 'bg-cyan-500 text-navy-950 font-bold shadow-glow-cyan'
                      : 'bg-slate-800/80 text-slate-300 hover:bg-slate-700 hover:text-white border border-slate-700/60'
                  }`}
                >
                  {proto}
                </button>
              );
            })}
          </div>

          {/* Quick Clear Button */}
          {hasActiveFilters && (
            <button
              onClick={handleResetFilters}
              className="flex items-center space-x-1 text-xs text-rose-400 hover:text-rose-300 transition-colors self-start lg:self-center font-mono cursor-pointer"
            >
              <RotateCcw className="w-3 h-3" />
              <span>Reset Filters</span>
            </button>
          )}
        </div>

        {/* Input Search Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
          {/* Search IP */}
          <div className="relative">
            <input
              type="text"
              placeholder="Search Host IP (src or dst)..."
              value={filters.ip || ''}
              onChange={(e) => handleInputChange('ip', e.target.value)}
              className="w-full bg-slate-950/70 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 font-mono placeholder:text-slate-400 focus:outline-none focus:border-cyan-500/60 transition-colors"
            />
          </div>

          {/* Search Port */}
          <div className="relative">
            <input
              type="number"
              placeholder="Port (80, 443, 53)..."
              value={filters.port || ''}
              onChange={(e) => handleInputChange('port', e.target.value)}
              className="w-full bg-slate-950/70 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 font-mono placeholder:text-slate-400 focus:outline-none focus:border-cyan-500/60 transition-colors"
            />
          </div>

          {/* Search Query / Info */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400" />
            <input
              type="text"
              placeholder="Search packet info & queries..."
              value={filters.search || ''}
              onChange={(e) => handleInputChange('search', e.target.value)}
              className="w-full bg-slate-950/70 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 font-mono placeholder:text-slate-400 focus:outline-none focus:border-cyan-500/60 transition-colors"
            />
          </div>
        </div>
      </div>

      {/* Dissected Packets Table */}
      <div className="overflow-x-auto min-h-[300px] relative">
        {isLoading && (
          <div className="absolute inset-0 bg-navy-950/60 backdrop-blur-[2px] z-10 flex items-center justify-center space-x-2 text-cyan-400 font-mono text-xs">
            <Loader2 className="w-4 h-4 animate-spin" />
            <span>Loading packet streams...</span>
          </div>
        )}

        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 font-mono text-[11px] uppercase tracking-wider">
              <th className="py-2.5 px-3 w-16">#</th>
              <th className="py-2.5 px-3 w-28">Protocol</th>
              <th className="py-2.5 px-3">Source</th>
              <th className="py-2.5 px-2 w-6 text-center"></th>
              <th className="py-2.5 px-3">Destination</th>
              <th className="py-2.5 px-3 w-20 text-right">Length</th>
              <th className="py-2.5 px-3">Dissected Info</th>
              <th className="py-2.5 px-3 w-12 text-center">Inspect</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono">
            {packets.length > 0 ? (
              packets.map((pkt) => {
                const badgeStyle =
                  PROTO_BADGES[pkt.highest_protocol] ||
                  'bg-slate-800 text-slate-300 border-slate-700';

                const srcDisplay = pkt.src_port
                  ? `${pkt.src_ip}:${pkt.src_port}`
                  : pkt.src_ip || pkt.src_mac || 'N/A';

                const dstDisplay = pkt.dst_port
                  ? `${pkt.dst_ip}:${pkt.dst_port}`
                  : pkt.dst_ip || pkt.dst_mac || 'N/A';

                return (
                  <tr
                    key={pkt.packet_num}
                    onClick={() => onSelectPacket(pkt)}
                    className="hover:bg-cyan-500/5 transition-colors cursor-pointer group"
                  >
                    <td className="py-2.5 px-3 text-slate-400 font-medium">
                      {pkt.packet_num}
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold border ${badgeStyle}`}
                      >
                        {pkt.highest_protocol}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-emerald-300 truncate max-w-[150px]" title={srcDisplay}>
                      {srcDisplay}
                    </td>
                    <td className="py-2.5 px-2 text-slate-400 text-center">
                      <ArrowRight className="w-3 h-3 inline text-slate-400" />
                    </td>
                    <td className="py-2.5 px-3 text-cyan-300 truncate max-w-[150px]" title={dstDisplay}>
                      {dstDisplay}
                    </td>
                    <td className="py-2.5 px-3 text-right text-slate-300">
                      {pkt.length} B
                    </td>
                    <td className="py-2.5 px-3 text-slate-300 truncate max-w-[320px]" title={pkt.info}>
                      {pkt.info}
                    </td>
                    <td className="py-2.5 px-3 text-center">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectPacket(pkt);
                        }}
                        className="p-1 rounded text-slate-400 group-hover:text-cyan-400 transition-colors"
                        title="View Layer Dissection"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                );
              })
            ) : (
              <tr>
                <td colSpan={8} className="py-12 text-center text-slate-400">
                  <div className="flex flex-col items-center justify-center space-y-2">
                    <Layers className="w-8 h-8 text-slate-400" />
                    <p className="text-sm font-sans font-medium text-slate-300">
                      No packets found matching current filters
                    </p>
                    <p className="text-xs text-slate-400 font-sans">
                      Try resetting filters or adjusting query terms
                    </p>
                  </div>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      <div className="p-3 border-t border-slate-800 bg-slate-950/60 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-400 font-mono gap-2">
        <div className="flex items-center space-x-2">
          <span>
            Showing page <strong className="text-white">{page}</strong> of{' '}
            <strong className="text-white">{totalPages}</strong>
          </span>
          <span>•</span>
          <span>
            Matched: <strong className="text-cyan-400">{totalMatched.toLocaleString()}</strong> packets
          </span>
        </div>

        <div className="flex items-center space-x-3">
          {/* Page size dropdown */}
          <div className="flex items-center space-x-1">
            <span>Show:</span>
            <select
              value={pageSize}
              onChange={(e) => onPageSizeChange(Number(e.target.value))}
              className="bg-slate-900 border border-slate-700 rounded px-2 py-0.5 text-slate-200 text-xs focus:outline-none"
            >
              <option value={25}>25</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
          </div>

          {/* Prev/Next buttons */}
          <div className="flex items-center space-x-1">
            <button
              onClick={() => onPageChange(page - 1)}
              disabled={page <= 1}
              className="p-1.5 rounded bg-slate-800 border border-slate-700 text-slate-300 hover:text-white disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer transition-colors"
              title="Previous Page"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              onClick={() => onPageChange(page + 1)}
              disabled={page >= totalPages}
              className="p-1.5 rounded bg-slate-800 border border-slate-700 text-slate-300 hover:text-white disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer transition-colors"
              title="Next Page"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
