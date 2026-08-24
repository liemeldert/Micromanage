"use client";

// Replaces the root layout when it fails, so MantineProvider and everything else the layout mounts is unavailable.

export default function GlobalError({
                                        error,
                                        reset,
                                    }: {
    error: Error & { digest?: string };
    reset: () => void;
}) {
    return (
        <html lang="en">
        <body
            style={{
                margin: 0,
                minHeight: "100vh",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontFamily: "system-ui, -apple-system, sans-serif",
                background: "#f8f9fa",
                color: "#212529",
            }}
        >
        <div style={{maxWidth: 520, padding: 24}}>
            <h1 style={{fontSize: 20, marginBottom: 8}}>Micromanage failed to start</h1>
            <p style={{fontSize: 14, lineHeight: 1.5, wordBreak: "break-word"}}>
                {error.message || "No message came with this error."}
            </p>
            {error.digest && (
                <p style={{fontSize: 12, color: "#868e96"}}>digest {error.digest}</p>
            )}
            <button
                type="button"
                onClick={reset}
                style={{
                    marginTop: 12,
                    padding: "8px 16px",
                    fontSize: 14,
                    borderRadius: 4,
                    border: "none",
                    background: "#228be6",
                    color: "white",
                    cursor: "pointer",
                }}
            >
                Try again
            </button>
        </div>
        </body>
        </html>
    );
}
