import React, { useState, useMemo } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Shield,
  Radio,
  Lock,
  Mail,
  User,
  Eye,
  EyeOff,
  AlertCircle,
  ArrowRight,
  CheckCircle2,
  XCircle,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export default function RegisterPage() {
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');

  const { register } = useAuth();
  const navigate = useNavigate();

  // Password validation rules computed in real-time
  const passwordChecks = useMemo(() => {
    return {
      minLength: password.length >= 8,
      hasUpper: /[A-Z]/.test(password),
      hasLower: /[a-z]/.test(password),
      hasNumberOrSymbol: /[\d\W]/.test(password),
      matchesConfirm: password.length > 0 && password === confirmPassword,
    };
  }, [password, confirmPassword]);

  const isFormValid = useMemo(() => {
    return (
      fullName.trim().length >= 2 &&
      email.trim().length > 3 &&
      passwordChecks.minLength &&
      passwordChecks.hasUpper &&
      passwordChecks.hasLower &&
      passwordChecks.hasNumberOrSymbol &&
      passwordChecks.matchesConfirm
    );
  }, [fullName, email, passwordChecks]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMessage('');

    if (!isFormValid) {
      if (!passwordChecks.matchesConfirm) {
        setErrorMessage('Passwords do not match.');
      } else {
        setErrorMessage('Please satisfy all password complexity requirements.');
      }
      return;
    }

    setIsSubmitting(true);
    try {
      await register({
        full_name: fullName.trim(),
        email: email.trim(),
        password,
        confirm_password: confirmPassword,
      });
      navigate('/dashboard', { replace: true });
    } catch (err) {
      setErrorMessage(err.message || 'Registration failed. Please check your information.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-navy-950 text-slate-100 flex flex-col justify-center items-center px-4 py-12 relative overflow-hidden">
      {/* Decorative Glows */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_80%_at_50%_-20%,rgba(6,182,212,0.15),rgba(255,255,255,0))] pointer-events-none" />
      <div className="absolute w-96 h-96 -top-24 -left-24 bg-cyan-600/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute w-96 h-96 -bottom-24 -right-24 bg-cyber-blue/10 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-md relative z-10">
        {/* Brand Header */}
        <div className="text-center mb-6">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-tr from-cyan-600 via-cyber-blue to-cyan-400 p-0.5 shadow-glow-cyan mx-auto flex items-center justify-center mb-3">
            <div className="w-full h-full bg-navy-950 rounded-[14px] flex items-center justify-center">
              <Radio className="w-7 h-7 text-cyan-400 animate-pulse" />
            </div>
          </div>
          <h1 className="text-2xl font-bold tracking-wider text-white">
            Packet<span className="text-cyan-400">Lens</span>
          </h1>
          <p className="text-xs uppercase font-mono tracking-widest text-cyan-500/80 font-medium mt-0.5">
            Create Analyst Account
          </p>
        </div>

        {/* Registration Card */}
        <div className="bg-navy-900/80 backdrop-blur-xl border border-slate-800 rounded-2xl p-7 shadow-2xl space-y-5">
          {/* Error Message Alert */}
          {errorMessage && (
            <div className="p-3.5 rounded-xl bg-rose-950/50 border border-rose-800/80 flex items-start space-x-3 text-rose-300 text-xs animate-shake">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <div className="leading-relaxed">{errorMessage}</div>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-3.5">
            {/* Full Name */}
            <div className="space-y-1">
              <label className="block text-xs font-medium text-slate-300 font-mono">
                Full Name
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                  <User className="w-4 h-4" />
                </div>
                <input
                  type="text"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="Alex Rivera"
                  required
                  autoComplete="name"
                  className="w-full pl-10 pr-4 py-2 rounded-xl bg-navy-950/70 border border-slate-700/80 text-white placeholder-slate-500 text-xs font-mono focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-all"
                />
              </div>
            </div>

            {/* Email Address */}
            <div className="space-y-1">
              <label className="block text-xs font-medium text-slate-300 font-mono">
                Work Email Address
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
                  className="w-full pl-10 pr-4 py-2 rounded-xl bg-navy-950/70 border border-slate-700/80 text-white placeholder-slate-500 text-xs font-mono focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-all"
                />
              </div>
            </div>

            {/* Password */}
            <div className="space-y-1">
              <label className="block text-xs font-medium text-slate-300 font-mono">
                Password
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                  <Lock className="w-4 h-4" />
                </div>
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Create a strong password"
                  required
                  autoComplete="new-password"
                  className="w-full pl-10 pr-10 py-2 rounded-xl bg-navy-950/70 border border-slate-700/80 text-white placeholder-slate-500 text-xs font-mono focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-all"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute inset-y-0 right-0 pr-3.5 flex items-center text-slate-400 hover:text-cyan-400 transition-colors cursor-pointer"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Confirm Password */}
            <div className="space-y-1">
              <label className="block text-xs font-medium text-slate-300 font-mono">
                Confirm Password
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                  <Lock className="w-4 h-4" />
                </div>
                <input
                  type={showConfirmPassword ? 'text' : 'password'}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Repeat your password"
                  required
                  autoComplete="new-password"
                  className="w-full pl-10 pr-10 py-2 rounded-xl bg-navy-950/70 border border-slate-700/80 text-white placeholder-slate-500 text-xs font-mono focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-all"
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  className="absolute inset-y-0 right-0 pr-3.5 flex items-center text-slate-400 hover:text-cyan-400 transition-colors cursor-pointer"
                >
                  {showConfirmPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Live Password Strength Checklist */}
            <div className="p-3 rounded-xl bg-slate-950/50 border border-slate-800 text-[11px] font-mono space-y-1.5">
              <span className="text-slate-400 block text-[10px] font-semibold uppercase tracking-wider mb-1">
                Password Security Requirements:
              </span>
              <div className="grid grid-cols-2 gap-1.5">
                <div className={`flex items-center space-x-1.5 ${passwordChecks.minLength ? 'text-emerald-400' : 'text-slate-500'}`}>
                  {passwordChecks.minLength ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
                  <span>8+ characters</span>
                </div>
                <div className={`flex items-center space-x-1.5 ${passwordChecks.hasUpper ? 'text-emerald-400' : 'text-slate-500'}`}>
                  {passwordChecks.hasUpper ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
                  <span>Uppercase (A-Z)</span>
                </div>
                <div className={`flex items-center space-x-1.5 ${passwordChecks.hasLower ? 'text-emerald-400' : 'text-slate-500'}`}>
                  {passwordChecks.hasLower ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
                  <span>Lowercase (a-z)</span>
                </div>
                <div className={`flex items-center space-x-1.5 ${passwordChecks.hasNumberOrSymbol ? 'text-emerald-400' : 'text-slate-500'}`}>
                  {passwordChecks.hasNumberOrSymbol ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
                  <span>Number / Symbol</span>
                </div>
              </div>
              {confirmPassword.length > 0 && (
                <div className={`pt-1 border-t border-slate-800/80 flex items-center space-x-1.5 ${passwordChecks.matchesConfirm ? 'text-emerald-400' : 'text-rose-400'}`}>
                  {passwordChecks.matchesConfirm ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
                  <span>{passwordChecks.matchesConfirm ? 'Passwords match' : 'Passwords do not match'}</span>
                </div>
              )}
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isSubmitting || !isFormValid}
              className="w-full mt-2 flex items-center justify-center space-x-2 py-2.5 px-4 rounded-xl bg-gradient-to-r from-cyan-500 to-cyber-blue hover:from-cyan-400 hover:to-cyber-blue text-navy-950 font-bold text-xs tracking-wide shadow-glow-cyan transition-all transform hover:-translate-y-0.5 active:translate-y-0 disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
            >
              {isSubmitting ? (
                <>
                  <Radio className="w-4 h-4 animate-spin text-navy-950" />
                  <span>Registering Analyst...</span>
                </>
              ) : (
                <>
                  <span>Create Account & Enter Dashboard</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Link to Login */}
          <div className="pt-3 border-t border-slate-800/80 text-center">
            <p className="text-xs text-slate-400">
              Already have an analyst account?{' '}
              <Link
                to="/login"
                className="font-semibold text-cyan-400 hover:text-cyan-300 transition-colors ml-1"
              >
                Sign In &rarr;
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
