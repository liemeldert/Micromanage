"use client";

import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { api } from "./api";

interface AuthState {
  token: string | null;
  tenantId: string | null;
  email: string | null;
}

interface AuthContext extends AuthState {
  login: (tenantId: string, email: string) => Promise<void>;
  logout: () => void;
  isAuthenticated: boolean;
}

const Ctx = createContext<AuthContext | null>(null);

const STORAGE_KEY = "mm_auth";

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<AuthState>({
    token: null,
    tenantId: null,
    email: null,
  });

  useEffect(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) setState(JSON.parse(raw));
    } catch {}
  }, []);

  const login = useCallback(async (tenantId: string, email: string) => {
    const res = await api.login(tenantId, email);
    const next = { token: res.access_token, tenantId, email };
    setState(next);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
  }, []);

  const logout = useCallback(() => {
    setState({ token: null, tenantId: null, email: null });
    localStorage.removeItem(STORAGE_KEY);
  }, []);

  return (
    <Ctx.Provider value={{ ...state, login, logout, isAuthenticated: !!state.token }}>
      {children}
    </Ctx.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
