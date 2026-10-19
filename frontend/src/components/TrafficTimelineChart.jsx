import React, { useMemo } from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from 'recharts';
import { TrendingUp } from 'lucide-react';

export default function TrafficTimelineChart({ packets = [], duration = 0 }) {
  // Group packets into chronological bins (10 to 30 intervals) for clean timeline charting
  const timelineData = useMemo(() => {
    if (!packets || packets.length === 0) return [];

    const sorted = [...packets].sort((a, b) => a.timestamp - b.timestamp);
    const minTime = sorted[0].timestamp;
    const maxTime = sorted[sorted.length - 1].timestamp;
    const totalSpan = Math.max(0.001, maxTime - minTime);

    // Create 15 equidistant bins
    const numBins = Math.min(20, Math.max(5, sorted.length));
    const binSize = totalSpan / numBins;

    const bins = Array.from({ length: numBins }, (_, i) => {
      const binStart = minTime + i * binSize;
      const binEnd = binStart + binSize;
      const label = `${(i * (totalSpan / numBins)).toFixed(2)}s`;
      return {
        label,
        timeSec: (i * (totalSpan / numBins)).toFixed(2),
        packets: 0,
        bytes: 0,
      };
    });

    for (const pkt of sorted) {
      let binIdx = Math.floor((pkt.timestamp - minTime) / binSize);
      if (binIdx >= numBins) binIdx = numBins - 1;
      if (binIdx < 0) binIdx = 0;
      bins[binIdx].packets += 1;
      bins[binIdx].bytes += pkt.length;
    }

    return bins;
  }, [packets]);

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload;
      return (
        <div className="bg-navy-900/95 border border-slate-700 p-3 rounded-lg shadow-xl backdrop-blur-md text-xs">
          <p className="font-mono text-cyan-400 font-semibold mb-1">
            Capture Elapsed: +{data.timeSec}s
          </p>
          <div className="space-y-0.5 font-mono text-slate-300">
            <p>
              Packet Rate: <span className="text-white font-bold">{data.packets}</span> packets
            </p>
            <p>
              Byte Volume: <span className="text-cyan-300 font-bold">{data.bytes.toLocaleString()}</span> B
            </p>
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="glass-panel rounded-xl p-5 border border-slate-800 flex flex-col justify-between">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center space-x-2">
          <TrendingUp className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-white">Traffic Activity Over Time</h3>
        </div>
        <span className="text-[11px] font-mono text-slate-400">
          Packets & Byte Rates
        </span>
      </div>

      <div className="h-64 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={timelineData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="trafficGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#06B6D4" stopOpacity={0.4} />
                <stop offset="95%" stopColor="#06B6D4" stopOpacity={0.0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" vertical={false} />
            <XAxis
              dataKey="label"
              stroke="#64748B"
              fontSize={10}
              tickLine={false}
              axisLine={{ stroke: '#1E293B' }}
            />
            <YAxis
              stroke="#64748B"
              fontSize={10}
              tickLine={false}
              axisLine={{ stroke: '#1E293B' }}
              allowDecimals={false}
            />
            <Tooltip content={<CustomTooltip />} />
            <Area
              type="monotone"
              dataKey="packets"
              stroke="#06B6D4"
              strokeWidth={2}
              fillOpacity={1}
              fill="url(#trafficGradient)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <div className="flex items-center justify-between pt-3 border-t border-slate-800/80 text-xs text-slate-400 font-mono">
        <span>Timeline Start (0.00s)</span>
        <span>Duration: {duration.toFixed(2)}s</span>
      </div>
    </div>
  );
}
