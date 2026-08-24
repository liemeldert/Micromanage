"use client";

import {createContext, useCallback, useContext, useEffect, useState} from "react";
import {api} from "./api";

interface AuthState {
    token: string | null;
    tenantId: string | null;
    email: string | null;
    role: string | null;
}

interface AuthContext extends AuthState {
    login: (tenantId: string, email: string, password: string) => Promise<void>;
    // Swap the session token in place, keeping the same identity and role. A password change returns a fresh token
    // because it invalidates every existing session for the account, this tab's included.
    setToken: (token: string) => void;
    logout: () => void;
    isAuthenticated: boolean;
    isAdmin: boolean;
    hydrated: boolean;
}

const Ctx = createContext<AuthContext | null>(null);

const STORAGE_KEY = "mm_auth";

export function AuthProvider({children}: { children: React.ReactNode }) {
    const [state, setState] = useState<AuthState>({
        token: null,
        tenantId: null,
        email: null,
        role: null,
    });
    // True once persisted auth has been read from localStorage. Treating a user as unauthenticated before this flips
    // bounces a logged-in user to /login on every refresh.
    const [hydrated, setHydrated] = useState(false);

    useEffect(() => {
        let restored: AuthState | null = null;
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            if (raw) {
                restored = {role: null, ...JSON.parse(raw)};
                setState(restored!);
            }
        } catch {
        }
        setHydrated(true);
        // Sessions saved without a role get it backfilled here, which also checks the token: a dead one 401s.
        if (restored?.token && !restored?.role) {
            api.me(restored.token).then((me) => {
                setState((s) => {
                    const next = {...s, role: me.role};
                    localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
                    return next;
                });
            }).catch(() => {
            });
        }
    }, []);

    const login = useCallback(async (tenantId: string, email: string, password: string) => {
        const res = await api.login(tenantId, email, password);
        const me = await api.me(res.access_token).catch(() => null);
        const next = {token: res.access_token, tenantId, email, role: me?.role ?? null};
        setState(next);
        localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    }, []);

    const setToken = useCallback((token: string) => {
        setState((s) => {
            const next = {...s, token};
            localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
            return next;
        });
    }, []);

    const logout = useCallback(() => {
        setState({token: null, tenantId: null, email: null, role: null});
        localStorage.removeItem(STORAGE_KEY);
    }, []);

    return (
        <Ctx.Provider
            value={{
                ...state,
                login,
                setToken,
                logout,
                isAuthenticated: !!state.token,
                isAdmin: state.role === "admin",
                hydrated,
            }}
        >
            {children}
        </Ctx.Provider>
    );
}

export function useAuth() {
    const ctx = useContext(Ctx);
    if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
    return ctx;
}
