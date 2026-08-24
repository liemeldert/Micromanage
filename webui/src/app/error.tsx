"use client";

// Route-level boundary for everything outside the dashboard shell: login, and any page that throws before the shell
// renders.

import {PageErrorModal} from "@/components/layout/PageErrorModal";

export default function AppError({
                                     error,
                                     reset,
                                 }: {
    error: Error & { digest?: string };
    reset: () => void;
}) {
    return <PageErrorModal error={error} reset={reset} title="Something broke"/>;
}
