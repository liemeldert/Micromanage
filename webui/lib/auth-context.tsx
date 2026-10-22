"use client";

import {createContext, useCallback, useContext, useEffect, useState} from "react";
import {api, ApiError} from "./api";

// The session token is in an HttpOnly cookie the browser cannot read. token holds this marker while the session
// is live and null otherwise, and api functions ignore its value.
export const SESSION_MARKER = "cookie";

interface AuthState {
    token: string | null;
    tenantId: string | null;
    email: string | null;
    role: string | null;
}

interface StoredIdentity {
    tenantId: string | null;
    email: string | null;
    role: string | null;
}

interface AuthContext extends AuthState {
    login: (tenantId: string, email: string, password: string) => Promise<void>;
    logout: () => Promise<void>;
    isAuthenticated: boolean;
    isAdmin: boolean;
    hydrated: boolean;
}

const Ctx = createContext<AuthContext | null>(null);

const STORAGE_KEY = "mm_auth";

const SIGNED_OUT: AuthState = {token: null, tenantId: null, email: null, role: null};

function storeIdentity(identity: StoredIdentity) {
    const {tenantId, email, role} = identity;
    localStorage.setItem(STORAGE_KEY, JSON.stringify({tenantId, email, role}));
}

export function AuthProvider({children}: { children: React.ReactNode }) {
    const [state, setState] = useState<AuthState>(SIGNED_OUT);
    // True once the stored identity has been checked against the controller. Treating a user as unauthenticated
    // before this flips bounces a signed-in user to /login on every refresh.
    const [hydrated, setHydrated] = useState(false);

    useEffect(() => {
        let stored: StoredIdentity | null = null;
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            if (raw) {
                const parsed = JSON.parse(raw);
                stored = {tenantId: parsed.tenantId ?? null, email: parsed.email ?? null, role: parsed.role ?? null};
            }
        } catch {
        }
        if (!stored) {
            setHydrated(true);
            return;
        }
        const identity = stored;
        api.me(SESSION_MARKER)
            .then((me) => {
                const next = {tenantId: me.tenant_id, email: me.email, role: me.role};
                storeIdentity(next);
                setState({token: SESSION_MARKER, ...next});
            })
            .catch((e) => {
                if (e instanceof ApiError && e.status === 401) {
                    localStorage.removeItem(STORAGE_KEY);
                    setState(SIGNED_OUT);
                } else {
                    // Any other failure keeps the session, and the pages report the error.
                    setState({token: SESSION_MARKER, ...identity});
                }
            })
            .finally(() => setHydrated(true));
    }, []);

    const login = useCallback(async (tenantId: string, email: string, password: string) => {
        await api.login(tenantId, email, password);
        const me = await api.me(SESSION_MARKER);
        const next = {tenantId, email, role: me.role};
        storeIdentity(next);
        setState({token: SESSION_MARKER, ...next});
    }, []);

    const logout = useCallback(async () => {
        await fetch("/api/session/logout", {method: "POST", headers: {"X-MM-Client": "web"}}).catch(() => null);
        setState(SIGNED_OUT);
        localStorage.removeItem(STORAGE_KEY);
    }, []);

    return (
        <Ctx.Provider
            value={{
                ...state,
                login,
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
