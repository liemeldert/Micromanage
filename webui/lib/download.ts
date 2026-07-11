// Trigger a browser "save file" for in-memory text. Used instead of navigating to
// an authenticated API endpoint via <a href>, which would carry no Authorization
// header and be rejected.
export function saveTextFile(
  filename: string,
  text: string,
  mime = "application/octet-stream",
): void {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
