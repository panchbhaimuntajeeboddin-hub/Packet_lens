import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { getCurrentUser, loginUser, registerUser, logoutUser } from '../services/api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [authError, setAuthError] = useState(null);

  // Check current session on mount via HttpOnly cookie
  const checkAuth = useCallback(async () => {
    try {
      setLoading(true);
      const currentUser = await getCurrentUser();
      setUser(currentUser);
      setAuthError(null);
    } catch (err) {
      setUser(null);
      setAuthError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    checkAuth();
  }, [checkAuth]);

  // Sign in analyst
  const login = async (credentials) => {
    setAuthError(null);
    try {
      const loggedUser = await loginUser(credentials);
      setUser(loggedUser);
      return loggedUser;
    } catch (err) {
      setAuthError(err.message);
      throw err;
    }
  };

  // Register new analyst
  const register = async (userData) => {
    setAuthError(null);
    try {
      const newUser = await registerUser(userData);
      setUser(newUser);
      return newUser;
    } catch (err) {
      setAuthError(err.message);
      throw err;
    }
  };

  // Sign out analyst
  const logout = async () => {
    try {
      await logoutUser();
    } catch (err) {
      console.warn('Logout API warning:', err);
    } finally {
      setUser(null);
    }
  };

  const value = {
    user,
    loading,
    authError,
    login,
    register,
    logout,
    checkAuth,
    isAuthenticated: !!user,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
