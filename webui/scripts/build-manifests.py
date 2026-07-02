#!/usr/bin/env python3
"""Generate webui/lib/manifests.generated.json from the community ProfileManifests
project (https://github.com/ProfileManifests/ProfileManifests).

Enumerates *every* Apple payload manifest (Manifests/ManifestsApple), rather than a
hand-maintained subset, so the profile editor's payload catalog stays in sync with
upstream. For each manifest the real (non-PFC, non-Payload-meta) subkeys are extracted
with full metadata; per-platform variants (…-iOS / …-macOS / …-tvOS) are merged with
per-field platform tags; a single level of nesting under a ``PayloadContent`` container
dict (SCEP, certificates) is flattened (tagged with ``parent``). Title comes from the
manifest's ``pfm_title`` and category from a keyword heuristic on the domain/title.

Run:  python3 webui/scripts/build-manifests.py   (needs git + network)
"""

import json
import os
import plistlib
import subprocess
import tempfile

REPO = "https://github.com/ProfileManifests/ProfileManifests"
SUBDIR = os.path.join("Manifests", "ManifestsApple")

# Manifests that aren't addable payloads (the profile wrapper, deprecated shells).
SKIP_FILES = {"Configuration.plist"}

META = {"PayloadType", "PayloadVersion", "PayloadIdentifier", "PayloadUUID",
        "PayloadDisplayName", "PayloadDescription", "PayloadOrganization"}
TYPES = {"string", "integer", "real", "boolean", "array", "dictionary", "data", "date"}
KEEP = {"iOS", "macOS", "tvOS"}
PLAT_SUFFIXES = ("-iOS", "-macOS", "-tvOS")

# First matching keyword wins (order matters, e.g. firewall -> Network before Security).
CATEGORY_RULES = [
    ("Network", ("wifi", "vpn", "network", "proxy", "cellular", "apn", "dns",
                 "firewall", "carrier", "relay", "airplay", "globalproxy", "hotspot")),
    ("Certificates", ("scep", "pkcs", "certificate", ".cert", "acme", "adcertificate",
                      "security.root", "activedirectorycertificate")),
    ("Accounts", ("mail", "caldav", "carddav", "exchange", "ldap", "account",
                  "subscribed", "googleaccount", "jabber", "aim", "contacts", "calendar")),
    ("Restrictions", ("applicationaccess", "restriction", "parental", "screentime")),
    ("Web", ("webclip", "webcontent", "domains", "safari")),
    ("Security", ("security", "passcode", "passwordpolicy", "password", "filevault",
                  "smartcard", "keychain", "identification", "screensaver", "gatekeeper",
                  "systempolicy", "privacy")),
    ("System", ("dock", "loginwindow", "softwareupdate", "energy", "mcx", "finder",
                "timemachine", "timeserver", "setupassistant", "dictionary", "printing",
                "menu", "desktop", "diagnostic", "notification", "system", "update", "mobileaccounts")),
]


def clean(s):
    return " ".join(str(s).split()) if s else None


def categorize(domain, title):
    hay = f"{domain} {title or ''}".lower()
    for cat, kws in CATEGORY_RULES:
        if any(k in hay for k in kws):
            return cat
    return "Other"


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


def base_name(fn):
    b = fn[:-6]  # strip ".plist"
    for sfx in PLAT_SUFFIXES:
        if b.endswith(sfx):
            return b[: -len(sfx)]
    return b


def build(apple_dir):
    # Group platform variants (…-iOS/…-macOS/…-tvOS) under a common base.
    groups = {}
    for fn in os.listdir(apple_dir):
        if not fn.endswith(".plist") or fn in SKIP_FILES:
            continue
        groups.setdefault(base_name(fn), []).append(fn)

    result = []
    for base, files in sorted(groups.items()):
        variants = []
        for fn in sorted(files):
            d = plistlib.load(open(os.path.join(apple_dir, fn), "rb"))
            sfx = next((s for s in PLAT_SUFFIXES if fn[:-6].endswith(s)), "")
            plats = ([sfx[1:]] if sfx
                     else [x for x in (d.get("pfm_platforms") or ["iOS", "macOS"]) if x in KEEP] or ["iOS"])
            variants.append((plats, d))

        domain = variants[0][1].get("pfm_domain")
        if not domain:
            continue
        title = clean(variants[0][1].get("pfm_title")) or domain

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
        if not order:  # meta-only manifest with no editable keys
            continue
        result.append({"domain": domain, "title": title, "category": categorize(domain, title),
                       "platforms": sorted(plats_all), "multiple": not unique,
                       "fields": [fields[k] for k in order]})
    return result


def main():
    dest = os.path.join(os.path.dirname(__file__), "..", "lib", "manifests.generated.json")
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(["git", "clone", "--depth", "1", "-q", REPO, tmp], check=True)
        result = build(os.path.join(tmp, SUBDIR))
    result.sort(key=lambda m: (m["category"], m["title"].lower()))
    json.dump(result, open(dest, "w"), ensure_ascii=False, separators=(",", ":"))
    by_cat = {}
    for m in result:
        by_cat[m["category"]] = by_cat.get(m["category"], 0) + 1
    print(f"Wrote {len(result)} manifests, {sum(len(m['fields']) for m in result)} fields -> {dest}")
    print("by category:", dict(sorted(by_cat.items())))


if __name__ == "__main__":
    main()
