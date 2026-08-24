"use client";

// Boundary inside the dashboard shell, so a page that throws leaves the navigation standing.

import {PageErrorModal} from "@/components/layout/PageErrorModal";

export default function DashboardError({
                                           error,
                                           reset,
                                       }: {
    error: Error & { digest?: string };
    reset: () => void;
}) {
    return <PageErrorModal error={error} reset={reset}/>;
}
