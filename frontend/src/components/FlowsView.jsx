import React from 'react';
import { ArrowRight, Users, MessageSquare } from 'lucide-react';

export default function FlowsView({ statistics, onSelectIp }) {
  if (!statistics) return null;

  const topTalkers = statistics.top_source_ips || [];
  const topConversations = statistics.top_conversations || [];

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      {/* Top Communicating Talkers */}
      <div className="glass-panel rounded-xl p-5 border border-slate-800">
        <div className="flex items-center space-x-2 mb-3">
          <Users className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-white">Top Active Endpoints (Talkers)</h3>
        </div>

        <div className="space-y-2">
          {topTalkers.length > 0 ? (
            topTalkers.map((talker, idx) => (
              <div
                key={idx}
                onClick={() => onSelectIp && onSelectIp(talker.ip)}
                className="flex items-center justify-between p-2.5 rounded-lg bg-slate-900/60 hover:bg-slate-800/80 border border-slate-800/80 transition-colors cursor-pointer group"
              >
                <div className="flex items-center space-x-3">
                  <span className="w-5 h-5 rounded-full bg-cyan-950 border border-cyan-800 text-[10px] font-mono font-bold text-cyan-400 flex items-center justify-center">
                    {idx + 1}
                  </span>
                  <div>
                    <span className="font-mono text-xs font-semibold text-white group-hover:text-cyan-300 transition-colors">
                      {talker.ip}
                    </span>
                    <p className="text-[11px] text-slate-400 font-mono">
                      {talker.byte_count.toLocaleString()} bytes transmitted
                    </p>
                  </div>
                </div>

                <div className="text-right">
                  <span className="font-mono text-xs font-bold text-cyan-400">
                    {talker.packet_count.toLocaleString()} pkts
                  </span>
                  <p className="text-[10px] text-slate-400 font-mono">
                    {talker.percentage_packets}% of total
                  </p>
                </div>
              </div>
            ))
          ) : (
            <p className="text-xs text-slate-400 py-4 text-center">No endpoint statistics available.</p>
          )}
        </div>
      </div>

      {/* Top IP Conversations */}
      <div className="glass-panel rounded-xl p-5 border border-slate-800">
        <div className="flex items-center space-x-2 mb-3">
          <MessageSquare className="w-4 h-4 text-emerald-400" />
          <h3 className="text-sm font-semibold text-white">Top IP Conversations (Flows)</h3>
        </div>

        <div className="space-y-2">
          {topConversations.length > 0 ? (
            topConversations.map((conv, idx) => (
              <div
                key={idx}
                className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800/80 text-xs font-mono"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2 truncate">
                    <span className="text-emerald-300 font-medium truncate max-w-[120px] sm:max-w-[150px]" title={conv.source_ip}>
                      {conv.source_ip}
                    </span>
                    <ArrowRight className="w-3 h-3 text-slate-400 shrink-0" />
                    <span className="text-cyan-300 font-medium truncate max-w-[120px] sm:max-w-[150px]" title={conv.destination_ip}>
                      {conv.destination_ip}
                    </span>
                  </div>

                  <div className="text-right shrink-0 ml-2">
                    <span className="font-bold text-white">{conv.packet_count} pkts</span>
                    <span className="text-slate-400 ml-1.5">({conv.byte_count} B)</span>
                  </div>
                </div>
              </div>
            ))
          ) : (
            <p className="text-xs text-slate-400 py-4 text-center">No conversational flows detected.</p>
          )}
        </div>
      </div>
    </div>
  );
}
