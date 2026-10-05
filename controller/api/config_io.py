"""I/O helpers for atomic and comment-preserving YAML configuration writes."""
import io
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

try:
    # Round-trip YAML re-serializes a document without deleting its comments, which never reach the parsed structure.
    # Optional: every write below falls back to pyyaml's safe_dump when it is absent.
    from ruamel.yaml import YAML as RoundTripYAML
except ImportError:  # pragma: no cover - depends on the installed image
    RoundTripYAML = None

from controller.models.tenant import Tenant
from controller.services import tenant_config

logger = logging.getLogger(__name__)

_atomic_write_yaml = tenant_config.write_yaml_atomic


def _round_trip_yaml(source: str):
    """A ruamel handler indented the way source is, so a save does not reformat the whole document."""
    sequence, offset = 4, 2
    try:
        from ruamel.yaml.util import load_yaml_guess_indent
        _doc, guessed, guessed_offset = load_yaml_guess_indent(source)
        if guessed:
            sequence = guessed
        if guessed_offset is not None:
            offset = guessed_offset
    except Exception:
        # Only the indent width is at stake here, so the defaults are a fine answer.
        pass
    handler = RoundTripYAML()
    handler.preserve_quotes = True
    handler.width = 4096
    handler.indent(mapping=2, sequence=sequence, offset=offset)
    return handler


def _sequences_align(current: List[Any], incoming: List[Any]) -> bool:
    """True if two lists describe the same items in the same order.

    Only then is a per-item merge safe; otherwise the caller replaces the list outright.
    """
    if len(current) != len(incoming):
        return False
    for existing_item, new_item in zip(current, incoming):
        if not isinstance(existing_item, dict) or not isinstance(new_item, dict):
            return False
        for key in ("id", "name"):
            if existing_item.get(key) != new_item.get(key):
                return False
    return True


def _apply_mapping(target: Dict[str, Any], incoming: Dict[str, Any]) -> None:
    """Overwrite target with incoming in place, reusing the existing nodes, and their comments, wherever the two agree.
    """
    for key, value in incoming.items():
        current = target.get(key)
        if isinstance(value, dict) and isinstance(current, dict):
            _apply_mapping(current, value)
        elif (isinstance(value, list) and isinstance(current, list)
              and _sequences_align(current, value)):
            for existing_item, new_item in zip(current, value):
                _apply_mapping(existing_item, new_item)
        else:
            target[key] = value
    for key in [k for k in target if k not in incoming]:
        del target[key]


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that refuses a mapping with a repeated key.

    pyyaml's default loader silently keeps only the last of a set of duplicate keys.
    """


def _no_duplicate_keys(loader, node, deep=False):
    seen = set()
    for key_node, _value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in seen
        except TypeError:  # unhashable key; SafeConstructor reports it below
            duplicate = False
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping", node.start_mark,
                f"found a duplicate key: {key!r}", key_node.start_mark)
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    lambda loader, node: _no_duplicate_keys(loader, node),
)


def _same_document(parsed: Any, data: Any) -> bool:
    """True if two parsed documents are the same document, types included.

    Python's == reads True as 1 and 1 as 1.0. Dumping both and comparing the text keeps those apart.
    """
    try:
        return (yaml.safe_dump(parsed, sort_keys=True, default_flow_style=False)
                == yaml.safe_dump(data, sort_keys=True, default_flow_style=False))
    except yaml.YAMLError:
        # Something in one of them has no safe representation, so they cannot be shown to be the same document.
        return False


def _round_trip_render(source: str, data: Dict[str, Any]) -> Optional[str]:
    """data rendered into the layout and comments of source, or None if the round trip could not be proven faithful
    (caller falls back to a plain dump; a document that keeps comments but not contents is worse than one with neither).
    """
    if RoundTripYAML is None:
        return None
    handler = _round_trip_yaml(source)
    try:
        document = handler.load(source)
    except Exception:
        logger.exception("config: round-trip load failed")
        return None
    if not isinstance(document, dict):
        return None
    buffer = io.StringIO()
    try:
        _apply_mapping(document, data)
        handler.dump(document, buffer)
    except Exception:
        logger.exception("config: round-trip render failed")
        return None
    rendered = buffer.getvalue()
    try:
        if _same_document(yaml.safe_load(rendered), data):
            return rendered
    except yaml.YAMLError:
        pass
    logger.warning("config: round-trip render did not reproduce the saved document; writing a plain dump instead")
    return None


def _config_document_text(path: Path, data: Dict[str, Any],
                          yaml_text: Optional[str] = None) -> Optional[str]:
    """The exact text to write for data, keeping its comments.

    Tries the client-submitted text, then the on-disk text, then a ruamel.yaml round trip, in that order.
    """
    on_disk = None
    try:
        if path.exists():
            on_disk = path.read_text(encoding="utf-8")
    except (OSError, ValueError):
        logger.exception("config: cannot read %s for its comments", path)
    for source in (yaml_text, on_disk):
        if not source:
            continue
        try:
            parsed = yaml.load(source, Loader=_StrictLoader)
        except yaml.YAMLError:
            # Unparseable, or parseable only by taking one of a pair of duplicate keys. Either way it is not usable as a
            # rendering of anything.
            continue
        if _same_document(parsed, data):
            return source
        if not isinstance(parsed, dict):
            continue
        rendered = _round_trip_render(source, data)
        if rendered is not None:
            return rendered
    return None


def _tenant_config_doc(
    tenant: Tenant, existing: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """The config.yaml mirror of a tenant row, merged onto existing.

    Every key the sync loop (controller/main.py) reads back must be written here, or the field resets on the next tick.
    """
    doc = dict(existing or {})
    tcfg = dict(doc.get("tenant") or {})
    tcfg["id"] = tenant.id
    tcfg["name"] = tenant.name
    tcfg["allowed_users"] = list(tenant.allowed_users or [])
    tcfg["s3"] = tenant.s3_config or {}
    tcfg["dep"] = {**(tcfg.get("dep") or {}), "enabled": tenant.dep_enabled}
    tcfg["ddm"] = {**(tcfg.get("ddm") or {}), "enabled": tenant.ddm_enabled}
    tcfg["device_naming"] = tenant.device_naming or {}
    doc["tenant"] = tcfg
    return doc
