import React from 'react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
} from 'recharts';
import { PieChart as PieIcon } from 'lucide-react';

const PROTOCOL_COLORS = {
  TCP: '#06B6D4',    // Cyan
  HTTP: '#0EA5E9',   // Cyber Sky
  DNS: '#A855F7',    // Cyber Purple
  UDP: '#10B981',    // Emerald
  ICMP: '#F59E0B',   // Amber
  ICMPv6: '#EAB308', // Yellow
  ARP: '#F43F5E',    // Rose
  IPv4: '#3B82F6',   // Blue
  IPv6: '#6366F1',   // Indigo
  Ethernet: '#64748B', // Slate
  Malformed: '#EF4444', // Red
};

const DEFAULT_COLORS = [
  '#06B6D4',
  '#A855F7',
  '#10B981',
  '#F59E0B',
  '#F43F5E',
  '#3B82F6',
  '#6366F1',
];

export default function ProtocolChart({ statistics, onSelectProtocol }) {
  if (!statistics?.protocol_distribution) return null;

  const data = Object.entries(statistics.protocol_distribution).map(
    ([name, count], index) => ({
      name,
      value: count,
      percentage: statistics.protocol_percentages?.[name] || 0,
      color:
        PROTOCOL_COLORS[name] ||
        DEFAULT_COLORS[index % DEFAULT_COLORS.length],
    })
  );

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      const item = payload[0].payload;
      return (
        <div className="bg-navy-900/95 border border-slate-700 p-3 rounded-lg shadow-xl backdrop-blur-md text-xs">
          <div className="flex items-center space-x-2 mb-1">
            <span
              className="w-2.5 h-2.5 rounded-full"
              style={{ backgroundColor: item.color }}
            />
            <span className="font-bold text-white font-mono text-sm">{item.name}</span>
          </div>
          <div className="text-slate-300 font-mono">
            <p>Packets: <span className="font-semibold text-cyan-300">{item.value.toLocaleString()}</span></p>
            <p>Traffic Share: <span className="font-semibold text-emerald-400">{item.percentage}%</span></p>
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="glass-panel rounded-xl p-5 border border-slate-800 flex flex-col justify-between">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center space-x-2">
          <PieIcon className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-white">Protocol Distribution</h3>
        </div>
        <span className="text-[11px] font-mono text-slate-400">
          {data.length} Detected
        </span>
      </div>

      <div className="h-64 w-full relative">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={55}
              outerRadius={85}
              paddingAngle={3}
              dataKey="value"
              onClick={(entry) => onSelectProtocol && onSelectProtocol(entry.name)}
              className="cursor-pointer"
            >
              {data.map((entry, index) => (
                <Cell
                  key={`cell-${index}`}
                  fill={entry.color}
                  stroke="#0B1120"
                  strokeWidth={2}
                />
              ))}
            </Pie>
            <Tooltip content={<CustomTooltip />} />
          </PieChart>
        </ResponsiveContainer>

        {/* Center label */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="text-xs text-slate-400 font-mono">Total</span>
          <span className="text-base font-bold font-mono text-white">
            {statistics.total_packets?.toLocaleString()}
          </span>
        </div>
      </div>

      {/* Legend Grid */}
      <div className="grid grid-cols-2 gap-2 pt-2 border-t border-slate-800/80">
        {data.map((item) => (
          <div
            key={item.name}
            onClick={() => onSelectProtocol && onSelectProtocol(item.name)}
            className="flex items-center justify-between p-1.5 rounded bg-slate-900/50 hover:bg-slate-800/70 border border-slate-800 transition-colors cursor-pointer text-xs"
          >
            <div className="flex items-center space-x-2 truncate">
              <span
                className="w-2 h-2 rounded-full shrink-0"
                style={{ backgroundColor: item.color }}
              />
              <span className="font-mono text-slate-300 font-medium truncate">
                {item.name}
              </span>
            </div>
            <span className="font-mono text-slate-400 text-[11px] ml-1">
              {item.percentage}%
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
