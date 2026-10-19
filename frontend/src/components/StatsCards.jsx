import React from 'react';
import { Activity, Database, Network, ShieldCheck, Zap, ArrowUpRight } from 'lucide-react';

export default function StatsCards({ statistics }) {
  if (!statistics) return null;

  const formatBytes = (bytes) => {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
  };

  const formatBitrate = (bps) => {
    if (!bps || bps === 0) return '0 bps';
    if (bps >= 1000000) return `${(bps / 1000000).toFixed(2)} Mbps`;
    if (bps >= 1000) return `${(bps / 1000).toFixed(2)} Kbps`;
    return `${bps.toFixed(0)} bps`;
  };

  // Find top protocol
  const protocols = Object.entries(statistics.protocol_distribution || {});
  const topProtocol = protocols.sort((a, b) => b[1] - a[1])[0] || ['None', 0];
  const topProtoPct = statistics.protocol_percentages?.[topProtocol[0]] || 0;

  const cards = [
    {
      title: 'Total Packets',
      value: statistics.total_packets?.toLocaleString() || '0',
      subValue: `Avg Bitrate: ${formatBitrate(statistics.bitrate_bps)}`,
      icon: Activity,
      accent: 'from-cyan-500 to-blue-500',
      badge: `${statistics.duration_seconds.toFixed(2)}s capture`,
      badgeColor: 'text-cyan-400 bg-cyan-950/80 border-cyan-800/40',
    },
    {
      title: 'Total Data Volume',
      value: formatBytes(statistics.total_bytes),
      subValue: `Avg Size: ${statistics.avg_packet_size} bytes/packet`,
      icon: Database,
      accent: 'from-blue-500 to-indigo-500',
      badge: `${statistics.total_bytes?.toLocaleString()} Bytes`,
      badgeColor: 'text-blue-400 bg-blue-950/80 border-blue-800/40',
    },
    {
      title: 'Unique IP Hosts',
      value: statistics.total_unique_ips?.toLocaleString() || '0',
      subValue: statistics.top_source_ips?.[0]
        ? `Top: ${statistics.top_source_ips[0].ip}`
        : 'Endpoints resolved',
      icon: Network,
      accent: 'from-emerald-500 to-teal-500',
      badge: `${statistics.top_conversations?.length || 0} Flows`,
      badgeColor: 'text-emerald-400 bg-emerald-950/80 border-emerald-800/40',
    },
    {
      title: 'Dominant Protocol',
      value: topProtocol[0],
      subValue: `${topProtocol[1]} packets (${topProtoPct}% share)`,
      icon: ShieldCheck,
      accent: 'from-purple-500 to-pink-500',
      badge: `${protocols.length} Protocols Identified`,
      badgeColor: 'text-purple-400 bg-purple-950/80 border-purple-800/40',
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <div
            key={idx}
            className="glass-panel rounded-xl p-4 border border-slate-800 hover:border-cyan-500/30 transition-all duration-300 relative overflow-hidden group shadow-lg"
          >
            {/* Top gradient glow line */}
            <div className={`absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r ${card.accent} opacity-60 group-hover:opacity-100 transition-opacity`} />

            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400 tracking-wide">
                {card.title}
              </span>
              <div className="w-8 h-8 rounded-lg bg-slate-800/80 border border-slate-700/60 flex items-center justify-center text-cyan-400 group-hover:scale-105 transition-transform">
                <Icon className="w-4 h-4 text-cyan-400" />
              </div>
            </div>

            <div className="mt-3">
              <div className="text-2xl font-bold font-mono tracking-tight text-white">
                {card.value}
              </div>
              <div className="mt-2 flex items-center justify-between text-xs">
                <span className="text-slate-400 truncate max-w-[140px]" title={card.subValue}>
                  {card.subValue}
                </span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${card.badgeColor}`}>
                  {card.badge}
                </span>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
