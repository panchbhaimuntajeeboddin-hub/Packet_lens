import React from 'react';
import {
  X,
  Shield,
  Layers,
  Network,
  Cpu,
  Globe,
  Clock,
  Hash,
  ArrowRight,
  Info,
} from 'lucide-react';

export default function PacketDetailsModal({ packet, onClose }) {
  if (!packet) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-navy-950/80 backdrop-blur-sm animate-fadeIn">
      <div className="relative w-full max-w-2xl bg-navy-900 border border-slate-800 rounded-2xl shadow-2xl p-6 overflow-hidden max-h-[90vh] flex flex-col">
        {/* Glowing top line */}
        <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-cyan-500 via-cyber-blue to-purple-500" />

        {/* Modal Header */}
        <div className="flex items-center justify-between pb-4 border-b border-slate-800 shrink-0">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400 font-mono font-bold text-sm">
              #{packet.packet_num}
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-base font-semibold text-white">Packet Dissection Details</h2>
                <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-cyan-500/15 text-cyan-400 border border-cyan-500/30">
                  {packet.highest_protocol}
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                {packet.timestamp_iso} | {packet.length} bytes
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Scrollable Dissection Body */}
        <div className="mt-4 space-y-4 overflow-y-auto pr-1 flex-1 text-xs">
          {/* Summary Banner */}
          <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 font-mono text-cyan-300">
            <span className="text-slate-500 mr-2 text-[11px] uppercase font-bold">Summary:</span>
            <span>{packet.info}</span>
          </div>

          {/* Layer 2: Data Link / Ethernet */}
          <div className="rounded-xl bg-slate-900/60 border border-slate-800/80 overflow-hidden">
            <div className="px-4 py-2.5 bg-slate-800/40 border-b border-slate-800 flex items-center space-x-2 text-slate-200 font-semibold">
              <Layers className="w-4 h-4 text-cyan-400" />
              <span>Layer 2 — Data Link Frame</span>
            </div>
            <div className="p-4 grid grid-cols-2 gap-3 font-mono">
              <div>
                <span className="text-slate-400 block text-[11px]">Source MAC:</span>
                <span className="text-slate-200 font-medium">{packet.src_mac || 'Broadcast / N/A'}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[11px]">Destination MAC:</span>
                <span className="text-slate-200 font-medium">{packet.dst_mac || 'Broadcast / N/A'}</span>
              </div>
            </div>
          </div>

          {/* Layer 3: Network Layer */}
          <div className="rounded-xl bg-slate-900/60 border border-slate-800/80 overflow-hidden">
            <div className="px-4 py-2.5 bg-slate-800/40 border-b border-slate-800 flex items-center space-x-2 text-slate-200 font-semibold">
              <Network className="w-4 h-4 text-emerald-400" />
              <span>Layer 3 — Network ({packet.network_protocol || 'Unknown'})</span>
            </div>
            <div className="p-4 grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono">
              <div>
                <span className="text-slate-400 block text-[11px]">Source IP:</span>
                <span className="text-emerald-300 font-medium">{packet.src_ip || 'N/A'}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[11px]">Destination IP:</span>
                <span className="text-emerald-300 font-medium">{packet.dst_ip || 'N/A'}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[11px]">IP Version:</span>
                <span className="text-slate-200 font-medium">{packet.ip_version ? `IPv${packet.ip_version}` : 'N/A'}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[11px]">TTL / Hop Limit:</span>
                <span className="text-slate-200 font-medium">{packet.ttl ?? 'N/A'}</span>
              </div>
            </div>
          </div>

          {/* Layer 4: Transport Layer */}
          {packet.transport_protocol && (
            <div className="rounded-xl bg-slate-900/60 border border-slate-800/80 overflow-hidden">
              <div className="px-4 py-2.5 bg-slate-800/40 border-b border-slate-800 flex items-center space-x-2 text-slate-200 font-semibold">
                <Cpu className="w-4 h-4 text-blue-400" />
                <span>Layer 4 — Transport ({packet.transport_protocol})</span>
              </div>
              <div className="p-4 grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono">
                <div>
                  <span className="text-slate-400 block text-[11px]">Source Port:</span>
                  <span className="text-blue-300 font-medium">{packet.src_port ?? 'N/A'}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[11px]">Destination Port:</span>
                  <span className="text-blue-300 font-medium">{packet.dst_port ?? 'N/A'}</span>
                </div>
                {packet.tcp_flags && packet.tcp_flags.length > 0 && (
                  <div className="col-span-2">
                    <span className="text-slate-400 block text-[11px] mb-1">Active TCP Flags:</span>
                    <div className="flex flex-wrap gap-1">
                      {packet.tcp_flags.map((flag) => (
                        <span
                          key={flag}
                          className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-950 text-blue-300 border border-blue-800/60"
                        >
                          {flag}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {packet.icmp_type !== null && packet.icmp_type !== undefined && (
                  <div>
                    <span className="text-slate-400 block text-[11px]">ICMP Type/Code:</span>
                    <span className="text-amber-300 font-medium">Type {packet.icmp_type} (Code {packet.icmp_code})</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Layer 7: Application Layer */}
          {packet.application_protocol && (
            <div className="rounded-xl bg-slate-900/60 border border-slate-800/80 overflow-hidden">
              <div className="px-4 py-2.5 bg-slate-800/40 border-b border-slate-800 flex items-center space-x-2 text-slate-200 font-semibold">
                <Globe className="w-4 h-4 text-purple-400" />
                <span>Layer 7 — Application ({packet.application_protocol})</span>
              </div>
              <div className="p-4 grid grid-cols-2 gap-3 font-mono">
                {packet.dns_query && (
                  <>
                    <div>
                      <span className="text-slate-400 block text-[11px]">Queried Domain:</span>
                      <span className="text-purple-300 font-medium">{packet.dns_query}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 block text-[11px]">Record Type:</span>
                      <span className="text-purple-300 font-medium">{packet.dns_query_type || 'A'}</span>
                    </div>
                  </>
                )}
                {packet.application_protocol === 'HTTP' && (
                  <div className="col-span-2">
                    <span className="text-slate-400 block text-[11px]">Protocol:</span>
                    <span className="text-sky-300 font-medium">HTTP Web Traffic (Port {packet.src_port || packet.dst_port})</span>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="pt-4 mt-2 border-t border-slate-800 flex items-center justify-end shrink-0">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors cursor-pointer"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
}
