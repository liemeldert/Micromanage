#!/usr/bin/env python3
"""Generate the profile editor's two generated artifacts.

webui/lib/manifests.generated.json is the editor's payload catalog, built from the
community ProfileManifests project (https://github.com/ProfileManifests/ProfileManifests).
It enumerates *every* Apple payload manifest (Manifests/ManifestsApple), rather than a
hand-maintained subset, so the profile editor's payload catalog stays in sync with
upstream. For each manifest the real (non-PFC, non-Payload-meta) subkeys are extracted
with full metadata; per-platform variants (...-iOS / ...-macOS / ...-tvOS) are merged with
per-field platform tags; a single level of nesting under a ``PayloadContent`` container
dict (SCEP, certificates) is flattened (tagged with ``parent``). Title comes from the
manifest's ``pfm_title`` and category from a keyword heuristic on the domain/title.

webui/lib/data-keys.generated.json is a separate, much smaller artifact: which keys of
which payload type a plist carries as <data> and Micromanage therefore holds as base64.
It is built by a wider scan than the catalog is (all four ProfileManifests directories
plus Apple's own mdm/profiles schemas, recursing the whole subkey tree instead of one
level) and stays out of manifests.generated.json because that file is imported into the
client bundle whole: megabytes of form metadata for two kilobytes of type knowledge.
Only keys whose manifest says the value is binary are listed; see classify_data_key.

Run:  python3 webui/scripts/build-manifests.py   (needs git + network + PyYAML)
"""

import json
import os
import plistlib
import subprocess
import tempfile

REPO = "https://github.com/ProfileManifests/ProfileManifests"
SUBDIR = os.path.join("Manifests", "ManifestsApple")

# The data-key scan reads all four manifest directories, not just Apple's: a
# third-party payload is exactly the case the built-in table used to miss.
MANIFEST_DIRS = ("ManifestsApple", "ManagedPreferencesApple",
                 "ManagedPreferencesApplications", "ManagedPreferencesDeveloper")

# Apple's own payload schemas, the second data-key source. Sparse-checkout recipe
# is the one controller/utils/payload_types.py's docstring documents.
APPLE_REPO = "https://github.com/apple/device-management"
APPLE_BRANCH = "release"
APPLE_SUBDIR = os.path.join("mdm", "profiles")
# Schema-helper documents, not payload types anyone can author.
APPLE_SKIP_TYPES = {"CommonPayloadKeys", "TopLevel", ".GlobalPreferences"}

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
    # Group platform variants (...-iOS/...-macOS/...-tvOS) under a common base.
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


#  data keys

# A plist <data> value is not always a base64 blob. Some keys wrap UTF-8 TEXT:
# com.apple.vpn.managed SharedSecret is a typed-in passphrase, a login script's
# filedata is the script itself, and a PEM bundle is armored text. Micromanage
# base64-decodes every key in this index before it builds the plist, so listing a
# text key here would corrupt a real deployment whenever the typed-in value
# happened to be base64-shaped. A key is listed only when its manifest gives
# positive evidence the value is binary, any evidence of text wins over that, and
# a key with neither is left out. Both lists are matched against the key's title
# and description, never against its value, and never against the domain name
# (com.apple.security.pem holds a DER blob despite the domain).
TEXT_EVIDENCE = ("utf-8", "utf8", "rtf", "plain text", "text file", "script",
                 ".pem", "valid pem", "shared secret", "pre-shared", "preshared",
                 "password", "passphrase", "secret")
BINARY_EVIDENCE = ("der-encoded", "der encoding", "der-encoding", "certificate",
                   ".p12", "pkcs", "binary representation", "fingerprint", "hash",
                   "png", "icon", "image", "logo", "font", "signature",
                   "public key", "encoded in base64", "encoded as base64",
                   "base64 data")


def classify_data_key(title, desc):
    """binary (list it), text (never list it), or unknown (leave it out)."""
    hay = f"{title or ''} {desc or ''}".lower()
    if any(w in hay for w in TEXT_EVIDENCE):
        return "text"
    if any(w in hay for w in BINARY_EVIDENCE):
        return "binary"
    return "unknown"


def usable_key(name):
    name = str(name or "")
    # {{value}} stands for a dictionary's dynamic keys, which have no fixed name.
    return bool(name) and name not in META and not name.startswith("PFC") and "{{" not in name


def scan(subkeys, containers, seen, elem_name, hit, kind):
    """Collect (key name, container path, title, description) for every data key.

    ``kind`` is "pfm" for a ProfileManifests plist or "apple" for one of Apple's
    mdm/profiles schemas; the two spell the same tree with different key names.
    An array's subkeys describe its elements, which carry no key of their own in
    a plist, so they answer to the array's name: RawPublicKeysElement inside the
    RawPublicKeys array is the key RawPublicKeys, at the granularity the decode
    matches on. Recursion is over the whole tree, not one level, because
    ManagedPreferences manifests nest several dictionaries deep.
    """
    if kind == "pfm":
        name_of, type_of, kids_of = "pfm_name", "pfm_type", "pfm_subkeys"
        title_of, desc_of = "pfm_title", "pfm_description"
        data_t, dict_t, array_t = "data", "dictionary", "array"
    else:
        name_of, type_of, kids_of = "key", "type", "subkeys"
        title_of, desc_of = "title", "content"
        data_t, dict_t, array_t = "<data>", "<dictionary>", "<array>"
    for s in subkeys or []:
        if not isinstance(s, dict) or id(s) in seen:
            continue  # YAML anchors make some of Apple's schemas self-referential
        name = elem_name or s.get(name_of)
        if not usable_key(name):
            continue
        t, kids = s.get(type_of), s.get(kids_of)
        if t == data_t:
            hit(str(name), containers, s.get(title_of), s.get(desc_of))
        elif t in (dict_t, array_t):
            below = containers if elem_name else containers + [str(name)]
            scan(kids, below, seen | {id(s)}, str(name) if t == array_t else None, hit, kind)


def build_data_keys(pm_root, apple_root):
    """The data-key index, plus the keys the classifier refused, for the report."""
    import yaml  # only this half needs it, and only when the generator runs

    index, excluded = {}, []

    def record(domain):
        def hit(name, containers, title, desc):
            if not domain:
                return
            verdict = classify_data_key(title, desc)
            if verdict != "binary":
                excluded.append((domain, name, verdict, clean(title) or clean(desc) or ""))
                return
            entry = index.setdefault(domain, {"keys": set(), "containers": set()})
            entry["keys"].add(name)
            entry["containers"].update(c for c in containers if c != name)
        return hit

    for sub in MANIFEST_DIRS:
        d = os.path.join(pm_root, "Manifests", sub)
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if not fn.endswith(".plist") or fn in SKIP_FILES:
                continue
            doc = plistlib.load(open(os.path.join(d, fn), "rb"))
            scan(doc.get("pfm_subkeys"), [], frozenset(), None,
                 record(doc.get("pfm_domain")), "pfm")

    for fn in sorted(os.listdir(apple_root)):
        if not fn.endswith(".yaml"):
            continue
        doc = yaml.safe_load(open(os.path.join(apple_root, fn)).read())
        pt = (doc.get("payload") or {}).get("payloadtype")
        if not pt or pt in APPLE_SKIP_TYPES:
            continue
        scan(doc.get("payloadkeys"), [], frozenset(), None, record(pt), "apple")

    return ({d: {"keys": sorted(v["keys"]), "containers": sorted(v["containers"])}
             for d, v in sorted(index.items())}, excluded)


def main():
    lib = os.path.join(os.path.dirname(__file__), "..", "lib")
    dest = os.path.join(lib, "manifests.generated.json")
    keys_dest = os.path.join(lib, "data-keys.generated.json")
    with tempfile.TemporaryDirectory() as tmp:
        pm = os.path.join(tmp, "profile-manifests")
        apple = os.path.join(tmp, "device-management")
        subprocess.run(["git", "clone", "--depth", "1", "-q", REPO, pm], check=True)
        subprocess.run(["git", "clone", "--depth", "1", "--branch", APPLE_BRANCH,
                        "--filter=blob:none", "--sparse", "-q", APPLE_REPO, apple], check=True)
        subprocess.run(["git", "-C", apple, "sparse-checkout", "set", APPLE_SUBDIR], check=True)
        result = build(os.path.join(pm, SUBDIR))
        data_keys, excluded = build_data_keys(pm, os.path.join(apple, APPLE_SUBDIR))
    result.sort(key=lambda m: (m["category"], m["title"].lower()))
    json.dump(result, open(dest, "w"), ensure_ascii=False, separators=(",", ":"))
    json.dump(data_keys, open(keys_dest, "w"), ensure_ascii=False, indent=1, sort_keys=True)
    by_cat = {}
    for m in result:
        by_cat[m["category"]] = by_cat.get(m["category"], 0) + 1
    print(f"Wrote {len(result)} manifests, {sum(len(m['fields']) for m in result)} fields -> {dest}")
    print("by category:", dict(sorted(by_cat.items())))
    print(f"Wrote {len(data_keys)} payload types, "
          f"{len({k for v in data_keys.values() for k in v['keys']})} key names -> {keys_dest}")
    for domain, name, verdict, why in sorted(set(excluded)):
        print(f"  left out ({verdict}): {domain} {name}: {why[:90]}")


if __name__ == "__main__":
    main()
