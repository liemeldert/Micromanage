// Minimal XML property-list (.plist / .mobileconfig) reader & writer.
// Supports the subset Apple configuration profiles use: dict, array, string,
// integer, real, true/false, date, data. Signed (PKCS7) profiles are not XML
// and will throw -- callers surface a friendly message.

export function parsePlist(xml: string): unknown {
  const doc = new DOMParser().parseFromString(xml, "application/xml");
  if (doc.querySelector("parsererror")) {
    throw new Error("Not valid XML -- the file may be a signed or binary profile.");
  }
  const root = doc.querySelector("plist")?.firstElementChild;
  if (!root) throw new Error("Empty or malformed plist.");
  return parseNode(root);
}

function parseNode(node: Element): unknown {
  switch (node.nodeName) {
    case "dict": {
      const obj: Record<string, unknown> = {};
      const kids = Array.from(node.children);
      for (let i = 0; i < kids.length; i += 2) {
        const key = kids[i];
        const val = kids[i + 1];
        if (key?.nodeName === "key" && val) obj[key.textContent ?? ""] = parseNode(val);
      }
      return obj;
    }
    case "array":
      return Array.from(node.children).map(parseNode);
    case "string":
      return node.textContent ?? "";
    case "integer":
      return parseInt(node.textContent ?? "0", 10);
    case "real":
      return parseFloat(node.textContent ?? "0");
    case "true":
      return true;
    case "false":
      return false;
    case "data":
      return (node.textContent ?? "").replace(/\s/g, "");
    case "date":
      return node.textContent ?? "";
    default:
      return node.textContent ?? "";
  }
}

function escapeXml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function buildNode(value: unknown, indent: number): string {
  const pad = "  ".repeat(indent);
  if (typeof value === "boolean") return `${pad}<${value ? "true" : "false"}/>`;
  if (typeof value === "number") {
    return Number.isInteger(value)
      ? `${pad}<integer>${value}</integer>`
      : `${pad}<real>${value}</real>`;
  }
  if (typeof value === "string") return `${pad}<string>${escapeXml(value)}</string>`;
  if (Array.isArray(value)) {
    if (value.length === 0) return `${pad}<array/>`;
    return `${pad}<array>\n${value.map((v) => buildNode(v, indent + 1)).join("\n")}\n${pad}</array>`;
  }
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) return `${pad}<dict/>`;
    const inner = entries
      .map(
        ([k, v]) =>
          `${"  ".repeat(indent + 1)}<key>${escapeXml(k)}</key>\n${buildNode(v, indent + 1)}`,
      )
      .join("\n");
    return `${pad}<dict>\n${inner}\n${pad}</dict>`;
  }
  return `${pad}<string></string>`;
}

export function buildPlist(value: unknown): string {
  return (
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n` +
    `<plist version="1.0">\n${buildNode(value, 0)}\n</plist>\n`
  );
}

//  .mobileconfig helpers 

export interface ImportedProfile {
  name?: string;
  identifier?: string;
  description?: string;
  payloads: Record<string, unknown>[];
}

export function parseMobileconfig(xml: string): ImportedProfile {
  const root = parsePlist(xml);
  if (!root || typeof root !== "object" || Array.isArray(root)) {
    throw new Error("This file is not a configuration profile.");
  }
  const r = root as Record<string, unknown>;
  const content = Array.isArray(r.PayloadContent)
    ? (r.PayloadContent as Record<string, unknown>[])
    : [];
  return {
    name: typeof r.PayloadDisplayName === "string" ? r.PayloadDisplayName : undefined,
    identifier: typeof r.PayloadIdentifier === "string" ? r.PayloadIdentifier : undefined,
    description: typeof r.PayloadDescription === "string" ? r.PayloadDescription : undefined,
    payloads: content,
  };
}

function uuid(): string {
  try {
    return crypto.randomUUID().toUpperCase();
  } catch {
    return "00000000-0000-0000-0000-000000000000";
  }
}

// Build a downloadable .mobileconfig wrapping one or more payloads, mirroring
// how the controller assembles the profile (PayloadContent: [...payloads]).
export function profileToMobileconfig(p: {
  id: string;
  name: string;
  description?: string;
  payloads: Record<string, unknown>[];
}): string {
  const content = p.payloads.map((payload, idx) => {
    const inner: Record<string, unknown> = { ...payload };
    inner.PayloadType = inner.PayloadType ?? "Configuration";
    inner.PayloadVersion = inner.PayloadVersion ?? 1;
    inner.PayloadIdentifier = inner.PayloadIdentifier ?? `com.micromanage.${p.id}.${idx}`;
    inner.PayloadUUID = inner.PayloadUUID ?? uuid();
    inner.PayloadDisplayName = inner.PayloadDisplayName ?? p.name;
    return inner;
  });

  const top: Record<string, unknown> = {
    PayloadContent: content,
    PayloadDisplayName: p.name,
    PayloadIdentifier: `com.micromanage.${p.id}`,
    PayloadType: "Configuration",
    PayloadUUID: uuid(),
    PayloadVersion: 1,
    ...(p.description ? { PayloadDescription: p.description } : {}),
  };
  return buildPlist(top);
}
