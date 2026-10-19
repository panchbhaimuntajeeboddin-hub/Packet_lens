import React, { useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import {
  Shield,
  Radio,
  Lock,
  Mail,
  Eye,
  EyeOff,
  AlertCircle,
  ArrowRight,
  CheckCircle2,
  Cpu,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export default function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');

  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  // Redirect destination after login (default /dashboard)
  const from = location.state?.from?.pathname || '/dashboard';

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMessage('');

    if (!email || !password) {
      setErrorMessage('Please enter both email and password.');
      return;
    }

    setIsSubmitting(true);
    try {
      await login({ email, password });
      navigate(from, { replace: true });
    } catch (err) {
      setErrorMessage(err.message || 'Authentication failed. Please verify your credentials.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-navy-950 text-slate-100 flex flex-col justify-center items-center px-4 py-12 relative overflow-hidden">
      {/* Decorative Cyber Background Grids & Glows */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_80%_at_50%_-20%,rgba(6,182,212,0.15),rgba(255,255,255,0))] pointer-events-none" />
      <div className="absolute w-96 h-96 -top-24 -left-24 bg-cyan-600/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute w-96 h-96 -bottom-24 -right-24 bg-cyber-blue/10 rounded-full blur-3xl pointer-events-none" />

      {/* Login Card Container */}
      <div className="w-full max-w-md relative z-10">
        {/* Header / Brand Logo */}
        <div className="text-center mb-8">
          <div className="w-16 h-16 rounded-2xl bg-gradient-to-tr from-cyan-600 via-cyber-blue to-cyan-400 p-0.5 shadow-glow-cyan mx-auto flex items-center justify-center mb-4">
            <div className="w-full h-full bg-navy-950 rounded-[14px] flex items-center justify-center">
              <Radio className="w-8 h-8 text-cyan-400 animate-pulse" />
            </div>
          </div>
          <h1 className="text-2xl font-bold tracking-wider text-white">
            Packet<span className="text-cyan-400">Lens</span>
          </h1>
          <p className="text-xs uppercase font-mono tracking-widest text-cyan-500/80 font-medium mt-1">
            Network Security & Traffic Analyzer
          </p>
        </div>

        {/* Form Panel */}
        <div className="bg-navy-900/80 backdrop-blur-xl border border-slate-800 rounded-2xl p-8 shadow-2xl space-y-6">
          <div>
            <h2 className="text-lg font-semibold text-white">Analyst Sign In</h2>
            <p className="text-xs text-slate-400 mt-1">
              Authenticate to access your private packet captures and traffic dashboards.
            </p>
          </div>

          {/* Error Banner */}
          {errorMessage && (
            <div className="p-3.5 rounded-xl bg-rose-950/50 border border-rose-800/80 flex items-start space-x-3 text-rose-300 text-xs animate-shake">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div className="leading-relaxed">{errorMessage}</div>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Email Field */}
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-slate-300 font-mono">
                Analyst Email Address
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                  <Mail className="w-4 h-4" />
                </div>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@secops.org"
                  required
                  autoComplete="email"
                  className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-navy-950/70 border border-slate-700/80 text-white placeholder-slate-500 text-xs font-mono focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-all"
                />
              </div>
            </div>

            {/* Password Field */}
            <div className="space-y-1.5">
              <div className="flex justify-between items-center">
                <label className="block text-xs font-medium text-slate-300 font-mono">
                  Password
                </label>
              </div>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                  <Lock className="w-4 h-4" />
                </div>
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  required
                  autoComplete="current-password"
                  className="w-full pl-10 pr-10 py-2.5 rounded-xl bg-navy-950/70 border border-slate-700/80 text-white placeholder-slate-500 text-xs font-mono focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-all"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute inset-y-0 right-0 pr-3.5 flex items-center text-slate-400 hover:text-cyan-400 transition-colors cursor-pointer"
                  title={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full mt-2 flex items-center justify-center space-x-2 py-2.5 px-4 rounded-xl bg-gradient-to-r from-cyan-500 to-cyber-blue hover:from-cyan-400 hover:to-cyber-blue text-navy-950 font-bold text-xs tracking-wide shadow-glow-cyan transition-all transform hover:-translate-y-0.5 active:translate-y-0 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
            >
              {isSubmitting ? (
                <>
                  <Radio className="w-4 h-4 animate-spin text-navy-950" />
                  <span>Verifying Credentials...</span>
                </>
              ) : (
                <>
                  <span>Sign In to Dashboard</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Footer Link to Registration */}
          <div className="pt-4 border-t border-slate-800/80 text-center">
            <p className="text-xs text-slate-400">
              Need access?{' '}
              <Link
                to="/register"
                className="font-semibold text-cyan-400 hover:text-cyan-300 transition-colors ml-1"
              >
                Create an Analyst Account &rarr;
              </Link>
            </p>
          </div>
        </div>

        {/* Security Trust Badges */}
        <div className="mt-6 flex items-center justify-center space-x-6 text-[11px] text-slate-400 font-mono">
          <div className="flex items-center space-x-1.5">
            <Shield className="w-3.5 h-3.5 text-cyan-400" />
            <span>Argon2id Hashed</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <Lock className="w-3.5 h-3.5 text-cyan-400" />
            <span>HttpOnly Session</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span>Strict Data Isolation</span>
          </div>
        </div>
      </div>
    </div>
  );
}
