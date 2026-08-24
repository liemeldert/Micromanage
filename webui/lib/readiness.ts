// GET /api/v1/readiness: whether the environment and this tenant have what each capability needs to run
// (an enrollment topic, a bucket for app packages, the webhook's shared secret). Admin only, since the body
// names deployment-wide settings.
//
// A 404 means either the running controller has no such route or the route is refusing to answer this caller.
// Both read as an absence of readiness data rather than an error: no extra retries, and nothing renders.

import {useCallback, useEffect, useState} from "react";
import {api, ApiError, type Readiness} from "./api";
import {useAuth} from "./auth-context";

/** Slow on purpose: deployment settings only change on a controller restart. */
export const READINESS_POLL_MS = 5 * 60 * 1000;

export function useReadiness(pollMs: number | null = null) {
    const {token, isAdmin} = useAuth();
    const [readiness, setReadiness] = useState<Readiness | null>(null);
    const [loading, setLoading] = useState(true);
    // Set only for errors worth surfacing, which excludes the 404.
    const [error, setError] = useState<string | null>(null);

    const load = useCallback(async () => {
        if (!token || !isAdmin) {
            setLoading(false);
            return;
        }
        try {
            const r = await api.getReadiness(token);
            setReadiness(r);
            setError(null);
        } catch (e) {
            if (e instanceof ApiError && e.status === 404) {
                setReadiness(null);
            } else {
                setError((e as Error).message);
            }
        } finally {
            setLoading(false);
        }
    }, [token, isAdmin]);

    useEffect(() => {
        load();
        if (!pollMs) return;
        const t = setInterval(load, pollMs);
        return () => clearInterval(t);
    }, [load, pollMs]);

    return {readiness, loading, error, reload: load};
}
