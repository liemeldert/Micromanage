// Fleet-wide rollout progress for a profile or an app, from the grouped counts GET /api/v1/stats/rollout returns.
// Counts describe deployment rows, not scope: a device with no row yet appears in no count, and "installed" is the
// last state each device confirmed rather than a live probe.

import {useCallback, useEffect, useState} from "react";
import {api, type RolloutItemStats, type RolloutStatsResponse} from "./api";
import {useAuth} from "./auth-context";

export interface RolloutCounts {
    installed: number;
    installing: number;
    pending: number;
    /**
     * Apps only, always 0 for profiles: the device acknowledged InstallApplication but no inventory report has named
     * the bundle id yet, so unlike "installing" there is no attempt left to wait on.
     */
    accepted: number;
    failed: number;
    /** Left the app's scope after being installed: no longer managed and no install coming, unlike "pending". */
    unscoped: number;
    /** Devices that have a deployment row of any status. */
    total: number;
}

export function toCounts(item: RolloutItemStats | undefined): RolloutCounts {
    const st = item?.by_status ?? {};
    return {
        installed: st.installed ?? 0,
        installing: st.installing ?? 0,
        pending: st.pending ?? 0,
        accepted: st.accepted ?? 0,
        failed: st.failed ?? 0,
        unscoped: st.unscoped ?? 0,
        total: item?.total ?? 0,
    };
}

/** Rows on their way but not confirmed: pending, installing and accepted together. */
export function inFlight(c: RolloutCounts): number {
    return c.pending + c.installing + c.accepted;
}

export function useRolloutStats(kind: "app" | "profile") {
    const {token} = useAuth();
    const [stats, setStats] = useState<RolloutStatsResponse | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const refresh = useCallback(async () => {
        if (!token) return;
        setLoading(true);
        setError(null);
        try {
            setStats(await api.getRolloutStats(token, kind));
        } catch (e) {
            setError((e as Error).message);
        } finally {
            setLoading(false);
        }
    }, [token, kind]);

    useEffect(() => {
        void refresh();
    }, [refresh]);

    return {stats, loading, error, refresh};
}
