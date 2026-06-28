#!/usr/bin/env python3
"""Generate webui/lib/manifests.generated.json from the community ProfileManifests
project (https://github.com/ProfileManifests/ProfileManifests).

Each Apple payload manifest plist is downloaded, its real (non-PFC, non-Payload-meta)
subkeys are extracted with full metadata, per-platform variants (…-iOS / …-macOS) are
merged with per-field platform tags, and a single level of nesting under a
``PayloadContent`` container dict (SCEP, certificates) is flattened into the form
(tagged with ``parent``). The emitted ``domain`` is the manifest's real ``pfm_domain``
(which can differ from the filename, e.g. MCX-EnergySaver -> com.apple.MCX).

So the editor always has the *full* key set per payload type rather than a hand-
maintained subset. Run:  python3 webui/scripts/build-manifests.py
"""

import glob
import json
import os
import plistlib
import tempfile
import urllib.request

BASE = "https://raw.githubusercontent.com/ProfileManifests/ProfileManifests/master/Manifests/ManifestsApple"

# filename-base -> (display title, editor category). Emitted domain is pfm_domain.
DOMAINS = {
    "com.apple.wifi.managed": ("Wi-Fi", "Network"),
    "com.apple.applicationaccess": ("Restrictions", "Security"),
    "com.apple.mobiledevice.passwordpolicy": ("Passcode policy", "Security"),
    "com.apple.MCX.FileVault2": ("FileVault", "Security"),
    "com.apple.security.firewall": ("Firewall", "Security"),
    "com.apple.security.scep": ("SCEP", "Security"),
    "com.apple.security.pkcs1": ("Certificate (PEM/DER)", "Security"),
    "com.apple.security.pkcs12": ("Certificate (PKCS#12)", "Security"),
    "com.apple.security.root": ("Root Certificate", "Security"),
    "com.apple.mail.managed": ("Mail", "Accounts"),
    "com.apple.caldav.account": ("Calendar (CalDAV)", "Accounts"),
    "com.apple.carddav.account": ("Contacts (CardDAV)", "Accounts"),
    "com.apple.webClip.managed": ("Web Clip", "Web"),
    "com.apple.dock": ("Dock", "System"),
    "com.apple.loginwindow": ("Login Window", "System"),
    "com.apple.SoftwareUpdate": ("Software Update", "System"),
    "com.apple.notificationsettings": ("Notifications", "System"),
    "com.apple.MCX-EnergySaver": ("Energy Saver", "System"),
}

META = {"PayloadType", "PayloadVersion", "PayloadIdentifier", "PayloadUUID",
        "PayloadDisplayName", "PayloadDescription", "PayloadOrganization"}
TYPES = {"string", "integer", "real", "boolean", "array", "dictionary", "data", "date"}
KEEP = {"iOS", "macOS", "tvOS"}
SUFFIXES = ["", "-iOS", "-macOS", "-tvOS"]


def clean(s):
    return " ".join(str(s).split()) if s else None


def make_field(s, platforms, parent=None):
    name, t = s.get("pfm_name"), s.get("pfm_type")
    if not name or name in META or str(name).startswith("PFC") or t not in TYPES:
        return None
    f = {"name": name, "title": clean(s.get("pfm_title")) or name, "type": t, "platforms": platforms}
    if parent:
        f["parent"] = parent
    desc, unit = clean(s.get("pfm_description")), s.get("pfm_value_unit")
    if desc:
        f["description"] = (desc[:280] + ("…" if len(desc) > 280 else "")) + (f" ({unit})" if unit else "")
    elif unit:
        f["description"] = f"In {unit}."
    dv = s.get("pfm_default")
    if dv is not None and isinstance(dv, (str, int, float, bool, list)):
        f["default"] = dv
    if s.get("pfm_require") == "always":
        f["required"] = True
    if s.get("pfm_supervised"):
        f["supervised"] = True
    if isinstance(s.get("pfm_range_min"), (int, float)):
        f["min"] = s["pfm_range_min"]
    if isinstance(s.get("pfm_range_max"), (int, float)):
        f["max"] = s["pfm_range_max"]
    if t == "string" and isinstance(s.get("pfm_range_list"), list) and s["pfm_range_list"]:
        f["options"] = [str(x) for x in s["pfm_range_list"]]
        tt = s.get("pfm_range_list_titles")
        if isinstance(tt, list) and len(tt) == len(f["options"]):
            f["optionLabels"] = {f["options"][i]: clean(tt[i]) for i in range(len(tt))}
    if "password" in name.lower():
        f["secret"] = True
    return f


def extract(subkeys, platforms):
    out = []
    for s in subkeys:
        if (s.get("pfm_name") == "PayloadContent" and s.get("pfm_type") == "dictionary"
                and isinstance(s.get("pfm_subkeys"), list)):
            for child in s["pfm_subkeys"]:
                f = make_field(child, platforms, parent="PayloadContent")
                if f:
                    out.append(f)
            continue
        f = make_field(s, platforms)
        if f:
            out.append(f)
    return out


def download(tmp):
    for base in DOMAINS:
        for sfx in SUFFIXES:
            fn = f"{base}{sfx}.plist"
            try:
                with urllib.request.urlopen(f"{BASE}/{fn}", timeout=30) as r:
                    open(os.path.join(tmp, fn), "wb").write(r.read())
            except Exception:
                pass


def build(tmp):
    result = []
    for base, (title, category) in DOMAINS.items():
        variants = []
        for sfx in SUFFIXES:
            p = os.path.join(tmp, f"{base}{sfx}.plist")
            if os.path.exists(p):
                d = plistlib.load(open(p, "rb"))
                plats = ([sfx[1:]] if sfx
                         else [x for x in (d.get("pfm_platforms") or ["iOS", "macOS"]) if x in KEEP] or ["iOS"])
                variants.append((plats, d))
        if not variants:
            print(f"  skip (not found): {base}")
            continue
        domain = variants[0][1].get("pfm_domain") or base
        fields, order, unique, plats_all = {}, [], False, set()
        for plats, d in variants:
            if d.get("pfm_unique"):
                unique = True
            plats_all.update(plats)
            for f in extract(d.get("pfm_subkeys", []), plats):
                key = (f.get("parent"), f["name"])
                if key in fields:
                    fields[key]["platforms"] = sorted(set(fields[key]["platforms"]) | set(f["platforms"]))
                else:
                    fields[key] = f
                    order.append(key)
        result.append({"domain": domain, "title": title, "category": category,
                       "platforms": sorted(plats_all), "multiple": not unique,
                       "fields": [fields[k] for k in order]})
        print(f"  {title} ({domain}): {len(order)} fields {sorted(plats_all)}")
    return result


def main():
    dest = os.path.join(os.path.dirname(__file__), "..", "lib", "manifests.generated.json")
    with tempfile.TemporaryDirectory() as tmp:
        download(tmp)
        result = build(tmp)
    json.dump(result, open(dest, "w"), ensure_ascii=False, separators=(",", ":"))
    print(f"\nWrote {len(result)} manifests, {sum(len(m['fields']) for m in result)} fields -> {dest}")


if __name__ == "__main__":
    main()
