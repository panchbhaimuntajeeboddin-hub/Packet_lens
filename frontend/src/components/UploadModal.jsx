import React, { useState, useRef } from 'react';
import { UploadCloud, X, AlertCircle, FileCode, CheckCircle2, Loader2, Sparkles } from 'lucide-react';
import { uploadCapture } from '../services/api';

export default function UploadModal({ isOpen, onClose, onUploadSuccess }) {
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [isProcessing, setIsProcessing] = useState(false);
  const [errorMessage, setErrorMessage] = useState(null);
  const fileInputRef = useRef(null);

  if (!isOpen) return null;

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const validateAndSetFile = (file) => {
    setErrorMessage(null);
    if (!file) return;

    const validExtensions = ['.pcap', '.pcapng', '.cap'];
    const hasValidExt = validExtensions.some((ext) => file.name.toLowerCase().endsWith(ext));

    if (!hasValidExt) {
      setErrorMessage(`Invalid file format '${file.name}'. Please upload a .pcap or .pcapng packet capture.`);
      return;
    }

    if (file.size === 0) {
      setErrorMessage('The selected file is empty (0 bytes).');
      return;
    }

    setSelectedFile(file);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const handleChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      validateAndSetFile(e.target.files[0]);
    }
  };

  const handleStartAnalysis = async () => {
    if (!selectedFile) return;

    setIsProcessing(true);
    setUploadProgress(0);
    setErrorMessage(null);

    try {
      const result = await uploadCapture(selectedFile, (percent) => {
        setUploadProgress(percent);
      });
      setIsProcessing(false);
      onUploadSuccess(result);
      onClose();
    } catch (err) {
      setIsProcessing(false);
      setErrorMessage(err.message || 'An error occurred while uploading and analyzing capture.');
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-navy-950/80 backdrop-blur-sm animate-fadeIn">
      <div className="relative w-full max-w-lg bg-navy-900 border border-slate-800 rounded-2xl shadow-2xl p-6 overflow-hidden">
        {/* Glowing cyber accent bar */}
        <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-cyan-500 via-cyber-blue to-purple-500" />

        {/* Modal Header */}
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div>
            <h2 className="text-lg font-semibold text-white">Upload Packet Capture</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Supports <span className="font-mono text-cyan-400">.pcap</span> and <span className="font-mono text-cyan-400">.pcapng</span> network captures
            </p>
          </div>
          <button
            onClick={onClose}
            disabled={isProcessing}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors disabled:opacity-50 cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Error Notification */}
        {errorMessage && (
          <div className="mt-4 p-3 rounded-lg bg-rose-950/50 border border-rose-800/80 flex items-start space-x-2 text-rose-300 text-xs">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-rose-400" />
            <span>{errorMessage}</span>
          </div>
        )}

        {/* Drag & Drop Area */}
        <div
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
          onClick={() => !isProcessing && fileInputRef.current?.click()}
          className={`mt-4 border-2 border-dashed rounded-xl p-8 text-center transition-all cursor-pointer ${
            dragActive
              ? 'border-cyan-400 bg-cyan-950/20 shadow-glow-cyan'
              : 'border-slate-700/80 hover:border-cyan-500/50 bg-slate-950/40'
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".pcap,.pcapng,.cap"
            onChange={handleChange}
            className="hidden"
            disabled={isProcessing}
          />

          <div className="flex flex-col items-center justify-center space-y-3">
            <div className="w-14 h-14 rounded-full bg-slate-800/80 border border-slate-700 flex items-center justify-center text-cyan-400 group-hover:scale-105 transition-transform">
              <UploadCloud className="w-7 h-7" />
            </div>

            {selectedFile ? (
              <div>
                <p className="text-sm font-semibold text-cyan-300 font-mono flex items-center justify-center space-x-1.5">
                  <FileCode className="w-4 h-4" />
                  <span>{selectedFile.name}</span>
                </p>
                <p className="text-xs text-slate-400 mt-1">
                  {(selectedFile.size / 1024).toFixed(1)} KB — Ready for analysis
                </p>
              </div>
            ) : (
              <div>
                <p className="text-sm font-medium text-slate-200">
                  Drag and drop your capture file here, or <span className="text-cyan-400 hover:underline">browse</span>
                </p>
                <p className="text-xs text-slate-400 mt-1">
                  Standard libpcap (.pcap) or modern Wireshark Next Generation (.pcapng) up to 50 MB
                </p>
              </div>
            )}
          </div>
        </div>

        {/* Upload Progress & Spinner */}
        {isProcessing && (
          <div className="mt-4 space-y-2">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-cyan-400 flex items-center space-x-2">
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                <span>
                  {uploadProgress < 100
                    ? `Uploading capture: ${uploadProgress}%`
                    : 'Dissecting packets & computing statistics...'}
                </span>
              </span>
              <span className="text-slate-400">{uploadProgress}%</span>
            </div>
            <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-cyan-500 to-cyber-blue transition-all duration-300 shadow-glow-cyan"
                style={{ width: `${uploadProgress}%` }}
              />
            </div>
          </div>
        )}

        {/* Modal Actions */}
        <div className="mt-6 flex items-center justify-end space-x-3">
          <button
            onClick={onClose}
            disabled={isProcessing}
            className="px-4 py-2 text-xs font-medium text-slate-400 hover:text-white transition-colors cursor-pointer disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            onClick={handleStartAnalysis}
            disabled={!selectedFile || isProcessing}
            className="flex items-center space-x-2 px-5 py-2 rounded-lg text-xs font-semibold bg-gradient-to-r from-cyan-500 to-cyber-blue hover:from-cyan-400 hover:to-cyber-blue text-navy-950 shadow-glow-cyan transition-all disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
          >
            {isProcessing ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                <span>Analyzing...</span>
              </>
            ) : (
              <>
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Start Dissection</span>
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
