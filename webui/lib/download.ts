// Trigger a browser save dialog for in-memory text. Navigating to an authenticated API endpoint through <a href>
// would carry no Authorization header and be rejected.
export function saveTextFile(
    filename: string,
    text: string,
    mime = "application/octet-stream",
): void {
    const blob = new Blob([text], {type: mime});
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    // Revoking in the same tick can race the browser's own read of the blob in some engines.
    setTimeout(() => URL.revokeObjectURL(url), 0);
}
