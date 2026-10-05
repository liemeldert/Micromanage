"""ATC run context tracking, wait barriers, timeline, and the gap ledger."""

import logging
from typing import Any, Dict, List, Optional, Tuple

from controller.models.tenant import FlowRun
from controller.services.atc_flow import _now
from controller.utils import coerce

logger = logging.getLogger(__name__)

# ==Context helpers==

# Signals where any occurrence for the device resumes a wait_for. The rest have to match what the run queued in
# context['expected'], and every ref has to arrive before the barrier lifts.
_REFLESS_SIGNALS = frozenset({"device_info", "checkin", "ddm_status"})

# Ceiling on the gap ledger; a validated flow already bounds entries by node count, this is for a hand-edited one.
GAP_LEDGER_MAX = 100

# Ledger entry kinds: not_queued (a step named ids and queued fewer), barrier_empty (a wait_for was skipped),
# never_arrived (a barrier gave up on refs the device never reported).
GAP_KINDS = frozenset({"not_queued", "barrier_empty", "never_arrived"})

# How bad a gap is: policy means the device was never entitled (scope, rollout wave); broken means the engine
# could not deliver something the flow named.
GAP_GRADES = ("policy", "broken")


def _signal_expected(run: FlowRun, signal: str, ref: Optional[str]) -> bool:
    """Whether this arrival belongs to the barrier the run is parked on. It says nothing about whether the barrier is
    done; _record_satisfied answers that."""
    if signal in _REFLESS_SIGNALS:
        return True
    expected = (run.context or {}).get("expected", {}).get(signal) or []
    return ref is not None and str(ref) in [str(x) for x in expected]


def _mark_satisfied(run: FlowRun, signal: str, ref: Optional[str]) -> None:
    if ref is None:
        return
    ctx = run.context or {}
    bucket = ctx.setdefault("satisfied", {}).setdefault(signal, [])
    if str(ref) not in [str(x) for x in bucket]:
        bucket.append(str(ref))
    run.context = ctx


def _wait_progress(run: FlowRun, signal: str) -> Tuple[int, int]:
    """(arrived, expected) for a signal's barrier."""
    ctx = run.context or {}
    expected = {str(x) for x in ((ctx.get("expected") or {}).get(signal) or [])}
    arrived = {str(x) for x in ((ctx.get("satisfied") or {}).get(signal) or [])}
    return len(expected & arrived), len(expected)


async def _record_satisfied(run: FlowRun, signal: str,
                            ref: Optional[str]) -> Tuple[int, int]:
    """Record one arrival against the run's barrier and report where that leaves it.

    Re-reads the row first: two refs for the same barrier can arrive close enough together that this run object is
    already stale by the time it is written, and losing one would hold the barrier short for good."""
    try:
        fresh = await FlowRun.get_or_none(id=run.id)
        stored = ((fresh.context or {}).get("satisfied") or {}).get(signal) if fresh else None
        for r in (stored or []):
            _mark_satisfied(run, signal, r)
    except Exception:
        logger.exception("ATC: re-reading arrivals failed for run %s", run.id)
    _mark_satisfied(run, signal, ref)
    return _wait_progress(run, signal)


def _expect(run: FlowRun, signal: str, refs: List[str]) -> None:
    ctx = run.context or {}
    expected = ctx.setdefault("expected", {})
    bucket = expected.setdefault(signal, [])
    for r in refs:
        if str(r) not in [str(x) for x in bucket]:
            bucket.append(str(r))
    run.context = ctx


def _consume_expected(run: FlowRun, signal: Optional[str]) -> None:
    """Clear a just-left wait_for's barrier: the refs wanted, which turned up, and any gate:false exemption. A
    later wait_for on the same signal must start from empty or it inherits stale arrivals. The gap ledger is
    deliberately not cleared here."""
    if not signal:
        return
    ctx = run.context or {}
    changed = False
    for key in ("expected", "satisfied"):
        bucket = ctx.get(key)
        if isinstance(bucket, dict) and signal in bucket:
            bucket[signal] = []
            changed = True
    ungated = ctx.get("ungated")
    if isinstance(ungated, dict) and ungated.pop(signal, None) is not None:
        changed = True
    if changed:
        run.context = ctx


# ==The gap ledger==
# What a barrier did not get. Append-only per run; release_device consults it before letting a device out.

def _gate_off(params: Optional[Dict[str, Any]]) -> bool:
    """True when the step carries gate: false in the flow document.

    Only a literal false counts. Anything else, including a truthy string hand-typed into flows.yaml, leaves the step
    holding the flow up, because the safe reading of an ambiguous value is the one that keeps the guard armed."""
    return (params or {}).get("gate") is False


def _mark_ungated(run: FlowRun, signal: str) -> None:
    """Record that the next barrier on this signal is allowed to hold nothing, because the step feeding it carries gate:
    false. _consume_expected drops the mark when that barrier is left, so it exempts one barrier and not the rest of the
    run."""
    ctx = run.context or {}
    ctx.setdefault("ungated", {})[signal] = True
    run.context = ctx


def _is_ungated(run: FlowRun, signal: Optional[str]) -> bool:
    return bool(((run.context or {}).get("ungated") or {}).get(signal))


def _record_gap(run: FlowRun, node_id: Optional[str], kind: str,
                signal: Optional[str], *, items: Optional[List[Dict[str, str]]] = None,
                grade: str = "policy", note: Optional[str] = None) -> None:
    """Append one gap to the run's ledger. items are the specific ids the step did not deliver, each with an
    actionable reason. An unrecognised kind is still written down rather than dropped, so a typo in a future
    caller cannot quietly disable this ledger."""
    ctx = run.context or {}
    ledger = ctx.setdefault("gaps", [])
    if kind not in GAP_KINDS:
        logger.warning("ATC: run %s recorded gap kind %r, which the board does not know how to render", run.id, kind)
    if len(ledger) >= GAP_LEDGER_MAX:
        return
    entry: Dict[str, Any] = {
        "at": _now().isoformat(), "node": node_id, "kind": kind,
        "signal": signal, "grade": grade if grade in GAP_GRADES else "policy",
    }
    if items:
        entry["items"] = items[:50]
    if note:
        entry["note"] = note
    ledger.append(entry)
    run.context = ctx


def _prior_gap_grade(run: FlowRun, signal: Optional[str]) -> Optional[str]:
    """How the last step that under-delivered on this signal was graded, which an empty barrier inherits. A rollout
    holding an app back explains the empty barrier and grades policy; nothing explaining it means the flow declared a
    wait nothing feeds, which grades broken."""
    for entry in reversed((run.context or {}).get("gaps") or []):
        if entry.get("signal") == signal and entry.get("kind") != "barrier_empty":
            return entry.get("grade")
    return None


def _record_unmet(run: FlowRun, node_id: Optional[str], signal: Optional[str]) -> None:
    """Refs a barrier wanted and never got, written down before it is cleared. Called on the timeout edge, where the
    author has decided the run carries on without them, so the ledger is the only record left that they are missing."""
    if not signal or signal in _REFLESS_SIGNALS:
        return
    ctx = run.context or {}
    expected = [str(x) for x in ((ctx.get("expected") or {}).get(signal) or [])]
    arrived = {str(x) for x in ((ctx.get("satisfied") or {}).get(signal) or [])}
    missing = [r for r in expected if r not in arrived]
    if not missing:
        return
    _record_gap(run, node_id, "never_arrived", signal, grade="broken",
                items=[{"id": r, "why": "the device never reported it",
                        "grade": "broken"} for r in missing])


def _gap_body(gaps: List[Dict[str, Any]]) -> str:
    """The middle of an alert summary: what is missing and which wait step turned out to be holding nothing."""
    missing: List[str] = []
    empty: List[str] = []
    for g in gaps:
        if g.get("kind") == "barrier_empty":
            empty.append(f"'{g.get('node')}'")
        for item in (g.get("items") or []):
            missing.append(f"{item.get('id')} ({item.get('why')})")
    bits: List[str] = []
    if missing:
        bits.append("it did not get " + ", ".join(missing[:6]))
    if empty:
        bits.append(f"the wait at {', '.join(empty[:4])} had nothing to hold")
    return "; ".join(bits) or "the flow could not account for what it installed"


def _drop_flow_snapshot(run: FlowRun) -> bool:
    """Forget the pinned flow definition on a run that is finished with it; it's the biggest thing this table writes (a
    full document copy per run, static passwords included). flow_hash still records which definition ran."""
    ctx = run.context or {}
    if ctx.pop("flow", None) is None:
        return False
    run.context = ctx
    return True


def _timeline(run: FlowRun, node_id: Optional[str], message: str) -> None:
    ctx = run.context or {}
    ctx.setdefault("timeline", []).append({
        "at": _now().isoformat(), "node": node_id, "message": message,
    })
    run.context = ctx


def _mark_visited(run: FlowRun, node_id: str) -> None:
    ctx = run.context or {}
    visited = ctx.setdefault("visited", [])
    if node_id not in visited:
        visited.append(node_id)
    run.context = ctx


def _mark_dirty(run: FlowRun) -> None:
    ctx = run.context or {}
    ctx["dirty"] = True
    run.context = ctx


_str_list = coerce.str_list
