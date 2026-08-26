"use client";

import {useCallback, useEffect, useMemo, useRef, useState} from "react";
import {
    ActionIcon,
    Alert,
    Box,
    Button,
    Center,
    Group,
    Loader,
    Modal,
    Paper,
    Popover,
    Stack,
    Switch,
    Text,
    Textarea,
    TextInput,
    Tooltip,
} from "@mantine/core";
import {
    IconAlertTriangle,
    IconCircleCheck,
    IconCloudCheck,
    IconCloudExclamation,
    IconCloudPause,
    IconDeviceFloppy,
    IconExclamationCircle,
    IconEye,
    IconInfoCircle,
    IconRocket,
    IconTrash,
} from "@tabler/icons-react";
import {modals} from "@mantine/modals";
import {notifications} from "@mantine/notifications";
import {
    api,
    type CatalogCommand,
    type Device,
    type DraftDiff,
    type FlowDoc,
    type FlowNode,
    type FlowNodeSpec,
    type FlowsConfig,
    type FlowsSummaryResponse,
    type FlowWarning,
    type GateFinding,
    type StartKind,
} from "../../../../lib/api";
import {type Group as GroupDef, useConfigResource, useTagRegistry} from "../../../../lib/config";
import {useAuth} from "../../../../lib/auth-context";
import {useBeforeUnload} from "../../../../lib/use-unsaved-changes";
import {FlowEditor} from "@/components/atc/FlowEditor";
import {FlowIssuesModal} from "@/components/atc/FlowIssuesModal";
import {FlowSaveConfirmModal} from "@/components/atc/FlowSaveConfirmModal";
import {FlowTabs} from "@/components/atc/FlowTabs";
import {FlowSwitcher} from "@/components/atc/FlowSwitcher";
import {FlowDiff} from "@/components/atc/FlowDiff";
import {PromoteDraftModal} from "@/components/atc/PromoteDraftModal";
import {
    ADMIN_ONLY_REASON,
    defaultEnrollmentFlow,
    emptyFlow,
    flowIdError,
    flowsFromConfig,
    flowToGraph,
    graphToNodes,
    issuesByNode,
    paletteForFlow,
    type SaveGuardReason,
    saveGuardReasons,
    slugifyFlowId,
    startKindsForFlow,
    validateFlowClient,
} from "@/components/atc/flow-utils";

// The canvas emits its nodes through graphToNodes, which rounds positions and drops keys it does not model, so a
// hand-authored document never matches its own re-emit exactly. Both sides of every comparison go through here first.
function normalizeFlows(doc: FlowsConfig | null): FlowDoc[] {
    if (!doc) return [];
    return flowsFromConfig(doc).map((f) => {
        const g = flowToGraph({...f, nodes: f.nodes ?? []}, []);
        return {...f, nodes: graphToNodes(g.nodes, g.edges)};
    });
}

function normalizedDoc(doc: FlowsConfig | null): string {
    if (!doc) return JSON.stringify(doc);
    return JSON.stringify({version: 2, flows: normalizeFlows(doc)});
}

/** Per-flow fingerprints of a saved snapshot, for the changed-flow count on the save button. Reads the same string
 * the whole-document dirty check compares, so the two cannot disagree. */
function flowFingerprints(snapshot: string): Map<string, string> {
    const out = new Map<string, string>();
    try {
        const parsed = JSON.parse(snapshot || "null") as FlowsConfig | null;
        for (const f of parsed?.flows ?? []) out.set(f.id, JSON.stringify(f));
    } catch {
        // An unparseable snapshot means nothing is known to be saved, so every flow reads as changed.
    }
    return out;
}

// How long the editor sits still before a draft is written back: long enough that a drag or a burst of typing is one
// write, short enough that little is only ever in the browser.
const AUTOSAVE_IDLE_MS = 1500;

/** Node lists that mean the same document. The canvas emits on selection and measurement as well as on edits, and a
 * document read from disk has not been through graphToNodes, so both sides are normalised first. A false positive here
 * would create a draft out of a mouse click. */
function sameNodes(a: FlowNode[], b: FlowNode[] | undefined): boolean {
    const norm = (nodes: FlowNode[]) => {
        const g = flowToGraph({id: "x", name: "x", nodes}, []);
        return JSON.stringify(graphToNodes(g.nodes, g.edges));
    };
    return norm(a) === norm(b ?? []);
}

/** sameNodes, blind to positions. A node's ui key holds only where its block sits on the canvas, so two lists equal
 * under this run identically. */
function sameNodesIgnoringUi(a: FlowNode[], b: FlowNode[] | undefined): boolean {
    const norm = (nodes: FlowNode[]) => {
        const g = flowToGraph({id: "x", name: "x", nodes}, []);
        return JSON.stringify(graphToNodes(g.nodes, g.edges).map((n) => ({...n, ui: undefined})));
    };
    return norm(a) === norm(b ?? []);
}

/** Whether a patch changes something the controller executes. Moving blocks is layout, so a patch differing only in
 * ui may be applied to a live flow; everything else belongs in a draft. */
function patchChangesContent(target: FlowDoc, patch: Partial<FlowDoc>): boolean {
    if (patch.name !== undefined && patch.name !== target.name) return true;
    if (patch.description !== undefined && (patch.description ?? "") !== (target.description ?? "")) return true;
    return !!(patch.nodes && !sameNodesIgnoringUi(patch.nodes, target.nodes));
}

const WARNING_FETCH_TIMEOUT_MS = 4000;

interface ServerVerdict {
    valid: boolean;
    errors: string[];
    flowWarnings: FlowWarning[];
    gateFindings: GateFinding[];
}

async function fetchServerVerdict(
    token: string,
    doc: FlowsConfig,
): Promise<ServerVerdict | null> {
    try {
        const res = await Promise.race([
            api.validateConfig(token, "flows", doc as unknown as Record<string, unknown>),
            new Promise<null>((resolve) => setTimeout(() => resolve(null), WARNING_FETCH_TIMEOUT_MS)),
        ]);
        if (!res || typeof res.valid !== "boolean") return null;
        return {
            valid: res.valid,
            errors: res.errors ?? [],
            flowWarnings: res.flow_warnings ?? [],
            gateFindings: (res as unknown as { gate_findings?: GateFinding[] }).gate_findings ?? [],
        };
    } catch {
        return null;
    }
}

// The editor fills the window: the canvas takes whatever the toolbar above it leaves, down to the bottom of the
// window, so the page never scrolls and never ends short of the bottom.
const CANVAS_STACK_GAP = 8;
const CANVAS_BOTTOM_SLACK = 8;

export default function ATCPage() {
    const {token, isAdmin} = useAuth();
    const {data, setData, loading, saving, save, version, setVersion} = useConfigResource<FlowsConfig>("flows", {
        version: 2,
        flows: [defaultEnrollmentFlow()],
    });
    const {tagNames} = useTagRegistry();

    const [catalog, setCatalog] = useState<FlowNodeSpec[]>([]);
    const [catalogState, setCatalogState] = useState<"loading" | "ready" | "error">("loading");
    const [startKinds, setStartKinds] = useState<StartKind[]>([]);
    const [commands, setCommands] = useState<CatalogCommand[]>([]);
    const [profileIds, setProfileIds] = useState<string[]>([]);
    const [appIds, setAppIds] = useState<string[]>([]);
    const [groups, setGroups] = useState<GroupDef[]>([]);
    const [devices, setDevices] = useState<Device[]>([]);
    const canvasRef = useRef<HTMLDivElement | null>(null);
    const [canvasHeight, setCanvasHeight] = useState(640);

    useEffect(() => {
        if (!canvasRef.current) return;
        const recalcCanvasHeight = () => {
            if (!canvasRef.current) return;
            const top = canvasRef.current.getBoundingClientRect().top;
            // Nothing is under the canvas, so it takes everything left down to the bottom of the window.
            const available = window.innerHeight - top - CANVAS_BOTTOM_SLACK;
            setCanvasHeight(Math.max(520, Math.round(available)));
        };
        const observer = new ResizeObserver(() => recalcCanvasHeight());
        observer.observe(document.body);
        window.addEventListener("resize", recalcCanvasHeight);
        recalcCanvasHeight();
        return () => {
            observer.disconnect();
            window.removeEventListener("resize", recalcCanvasHeight);
        };
    }, []);

    useEffect(() => {
        if (!token) return;
        setCatalogState("loading");
        api
            .getFlowStepCatalog(token)
            .then((c) => {
                setCatalog(c.nodes);
                setStartKinds(c.start_kinds ?? []);
                setCatalogState(c.nodes?.length ? "ready" : "error");
            })
            .catch(() => setCatalogState("error"));
        api.getCommandCatalog(token).then((c) => setCommands(c.commands)).catch(() => {
        });
        api.getConfig(token, "profiles").then((p) => setProfileIds(((p?.profiles as {
            id: string
        }[]) ?? []).map((x) => x.id))).catch(() => {
        });
        api.getConfig(token, "apps").then((a) => setAppIds(((a?.apps as {
            id: string
        }[]) ?? []).map((x) => x.id))).catch(() => {
        });
        api.getConfig(token, "groups").then((g) => setGroups(((g?.groups as GroupDef[]) ?? []))).catch(() => {
        });
        api.listDevices(token, {state: "enrolled", limit: 500}).then((r) => setDevices(r.devices)).catch(() => {
        });
    }, [token]);

    // The flow list, whatever the server sent. flowsFromConfig carries the permanent flag through a legacy
    // single-flow response, which is what keeps the enrollment flow pinned and its tab un-closable.
    const flows: FlowDoc[] = useMemo(() => {
        const list = flowsFromConfig(data);
        if (!list.length) return [defaultEnrollmentFlow()];
        return list.map((f) => (f.nodes ? f : {...f, nodes: []}));
    }, [data]);

    const permanentFlow = useMemo(() => {
        return flows.find((f) => f.permanent && !f.draft_of) ?? flows[0];
    }, [flows]);

    // Working set of open tabs
    const [openFlowIds, setOpenFlowIds] = useState<string[]>(() => {
        return [permanentFlow?.id ?? "enrollment"];
    });

    useEffect(() => {
        if (permanentFlow && !openFlowIds.includes(permanentFlow.id)) {
            setOpenFlowIds((prev) => [permanentFlow.id, ...prev]);
        }
    }, [permanentFlow, openFlowIds]);

    const [activeFlowId, setActiveFlowId] = useState<string>(permanentFlow?.id ?? "enrollment");

    const activeFlow: FlowDoc = useMemo(() => {
        const found = flows.find((f) => f.id === activeFlowId);
        if (found) return found;
        return permanentFlow ?? flows[0];
    }, [flows, activeFlowId, permanentFlow]);

    useEffect(() => {
        if (activeFlow && activeFlow.id !== activeFlowId) {
            setActiveFlowId(activeFlow.id);
        }
    }, [activeFlow, activeFlowId]);

    const [docRevision, setDocRevision] = useState(0);
    const wasLoading = useRef(true);
    useEffect(() => {
        if (wasLoading.current && !loading) setDocRevision((r) => r + 1);
        wasLoading.current = loading;
    }, [loading]);

    const canvasReady = !loading && data !== null && docRevision > 0 && catalogState === "ready";

    // The document as last loaded or written. State rather than a ref, because the memos that decide whether there is
    // unsaved work read it and have to re-run when it changes.
    const [savedSnapshot, setSavedSnapshot] = useState("");
    useEffect(() => {
        if (docRevision > 0) setSavedSnapshot(normalizedDoc(data));
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [docRevision]);

    // Which flows the saved document holds at all. A flow absent from here was created this session and exists nowhere
    // but this browser.
    const savedFlowIds = useMemo(
        () => new Set(flowFingerprints(savedSnapshot).keys()),
        [savedSnapshot],
    );

    const patchFlow = useCallback(
        (targetId: string, patch: Partial<FlowDoc>) => {
            setData((prev) => {
                const curFlows = flowsFromConfig(prev);
                if (!curFlows.length) curFlows.push(defaultEnrollmentFlow());
                const nextFlows = curFlows.map((f) => (f.id === targetId ? {...f, ...patch} : f));
                return {version: 2, flows: nextFlows};
            });
        },
        [setData],
    );

    // Which flow the canvas is showing. A handoff into a fresh draft is the one time the tab changes without the graph
    // changing, and rebuilding the canvas there would throw away the viewport mid-edit, so the epoch stays put.
    const [canvasEpoch, setCanvasEpoch] = useState(0);
    const canvasFlowId = useRef<string | null>(null);
    const handoffTo = useRef<string | null>(null);
    useEffect(() => {
        if (!activeFlow || canvasFlowId.current === activeFlow.id) return;
        const isHandoff = handoffTo.current === activeFlow.id;
        handoffTo.current = null;
        canvasFlowId.current = activeFlow.id;
        if (!isHandoff) {
            inheritedCanvas.current = null;
            setCanvasEpoch((e) => e + 1);
        }
    }, [activeFlow]);

    // Set while the draft behind a first edit is being created. A second edit arriving in those few hundred
    // milliseconds does not ask for a second draft: it queues here and merges into the draft when the POST answers.
    const handoffInFlight = useRef<{ liveId: string; patches: Partial<FlowDoc>[] } | null>(null);

    // A draft that took over the canvas from its live flow without a rebuild. The graph on screen was built under the
    // live flow's id and is now the draft's content, so emits still carrying the old name belong to the draft.
    const inheritedCanvas = useRef<{ from: string; to: string } | null>(null);

    /** Move the work on the canvas into a draft of live, and follow it.
     *
     * The server builds the draft from what is on disk, and the edit that triggered this is written into the draft
     * rather than onto the live flow, so the live flow keeps running unchanged until somebody promotes. */
    const handOffToDraft = useCallback(
        async (live: FlowDoc, patch: Partial<FlowDoc>, note = "") => {
            if (!token) return;
            const inFlight = handoffInFlight.current;
            if (inFlight) {
                if (inFlight.liveId === live.id) {
                    inFlight.patches.push(patch);
                } else {
                    // Two handoffs cannot share the document version, so this edit is refused rather than
                    // applied to the wrong flow.
                    notifications.show({
                        color: "red",
                        title: "Another draft is still being created",
                        message: "This edit was not applied. Try it again in a moment.",
                    });
                }
                return;
            }
            handoffInFlight.current = {liveId: live.id, patches: []};
            try {
                const res = await api.createFlowDraft(token, live.id, note, version);
                if (res.version) setVersion(res.version);
                // Edits queued while the POST was outstanding replay in order on top of the triggering one: later
                // patches win per key.
                const queued = handoffInFlight.current?.patches ?? [];
                const draft: FlowDoc = Object.assign({}, res.data, patch, ...queued);
                setData((prev) => ({
                    version: 2,
                    flows: [...flowsFromConfig(prev), draft],
                }));
                // The server has written res.data and nothing more, so only that joins the saved baseline. The
                // triggering edit and the queue read as unsaved work on the draft, and autosave writes them.
                setSavedSnapshot((prev) => normalizedDoc({
                    version: 2,
                    flows: [...flowsFromConfig(JSON.parse(prev || "null")), res.data],
                }));
                handoffTo.current = draft.id;
                inheritedCanvas.current = {from: live.id, to: draft.id};
                setOpenFlowIds((prev) => (prev.includes(draft.id) ? prev : [...prev, draft.id]));
                setActiveFlowId(draft.id);
                notifications.show({
                    color: "blue",
                    title: `Editing a draft of ${live.name || live.id}`,
                    message: "Drafts save themselves. Review and publish when you want this live.",
                });
            } catch (e) {
                // Fail closed: the edit and the queue are dropped rather than applied to the live flow, and the
                // canvas rebuilds from the document, which still holds the flow as saved.
                inheritedCanvas.current = null;
                setCanvasEpoch((v) => v + 1);
                notifications.show({
                    color: "red",
                    title: "Could not start a draft",
                    message: `${(e as Error).message.replace(/\.$/, "")}. The edit was not applied; the canvas shows the flow as saved.`,
                });
            } finally {
                handoffInFlight.current = null;
            }
        },
        [token, version, setVersion, setData],
    );

    /** An edit to nodes, name or description never reaches a live flow. It goes to that flow's draft, created on the
     * spot the first time. The enabled switch does not come through here, since a draft does not carry it, so
     * switching a flow off stays a live-flow decision. */
    const editFlowContent = useCallback(
        (target: FlowDoc | undefined, patch: Partial<FlowDoc>) => {
            if (!target) return;
            if (target.draft_of || !isAdmin) {
                patchFlow(target.id, patch);
                return;
            }
            // A flow the saved document has never held is not live anywhere, and there is nothing on disk to build
            // a draft from. The ordinary Save writes it.
            if (!savedFlowIds.has(target.id)) {
                patchFlow(target.id, patch);
                return;
            }
            const existing = flows.find((f) => f.draft_of === target.id);
            if (existing) {
                // Unreachable backstop: the editor renders read-only while a draft exists. An edit that slips
                // through is refused and the draft is opened instead.
                notifications.show({
                    color: "yellow",
                    title: `${target.name || target.id} already has a draft`,
                    message: "Changes belong in the draft, so that is where this opened.",
                });
                handleSelectFlow(existing.id);
                return;
            }
            // Positions decide nothing the controller executes, so a drag that only moves blocks is applied to the
            // live flow and committed by Save.
            if (!patchChangesContent(target, patch)) {
                patchFlow(target.id, patch);
                return;
            }
            void handOffToDraft(target, patch);
        },
        // handleSelectFlow is declared below and is stable for a render, which is all this needs; listing it here
        // would force it above its own state.
        // eslint-disable-next-line react-hooks/exhaustive-deps
        [flows, isAdmin, patchFlow, handOffToDraft, savedFlowIds],
    );

    const editActiveFlow = useCallback(
        (patch: Partial<FlowDoc>) => editFlowContent(activeFlow, patch),
        [activeFlow, editFlowContent],
    );

    const onCanvasChange = useCallback(
        (p: { nodes: FlowNode[]; flowId: string }) => {
            // Whose canvas this is. A graph the tab bar has already moved on from still emits for a moment (a drag
            // still in progress, a late measurement), and writing that onto the newly selected flow would replace its
            // work with the flow just left.
            const inherited = inheritedCanvas.current;
            const targetId =
                p.flowId === activeFlow?.id
                    ? activeFlow.id
                    : inherited && p.flowId === inherited.from && activeFlow?.id === inherited.to
                        ? inherited.to
                        : null;
            if (!targetId) return;
            const target = flows.find((f) => f.id === targetId);
            if (!target) return;
            // Selection and measurement come through here too. Only a document that differs is an edit.
            if (sameNodes(p.nodes, target.nodes)) return;
            editFlowContent(target, {nodes: p.nodes});
        },
        [activeFlow, flows, editFlowContent],
    );

    const scopedCatalog = useMemo(() => {
        return paletteForFlow(catalog, activeFlow, data);
    }, [catalog, activeFlow, data]);

    const scopedStartKinds = useMemo(() => {
        return startKindsForFlow(startKinds, activeFlow, data);
    }, [startKinds, activeFlow, data]);

    // Validation issues
    const clientIssues = useMemo(
        () => (catalog.length && activeFlow ? validateFlowClient(activeFlow, catalog) : []),
        [activeFlow, catalog],
    );
    const nodeIssues = useMemo(() => issuesByNode(clientIssues), [clientIssues]);

    const [issuesOpen, setIssuesOpen] = useState(false);
    const [issuesBlocking, setIssuesBlocking] = useState(false);
    const openIssues = () => {
        setIssuesBlocking(false);
        setIssuesOpen(true);
    };

    const [focusNode, setFocusNode] = useState<{ id: string; nonce: number } | null>(null);
    const goToNode = useCallback(
        (id: string) => setFocusNode((prev) => ({id, nonce: (prev?.nonce ?? 0) + 1})),
        [],
    );

    // Server flow warnings
    const [serverWarnings, setServerWarnings] = useState<FlowWarning[]>([]);
    const [serverGateFindings, setServerGateFindings] = useState<GateFinding[]>([]);

    useEffect(() => {
        if (!token || !data || docRevision === 0) return;
        let stale = false;
        fetchServerVerdict(token, data).then((v) => {
            if (!stale && v) {
                setServerWarnings(v.flowWarnings);
                setServerGateFindings(v.gateFindings);
            }
        });
        return () => {
            stale = true;
        };
    }, [token, data, docRevision]);

    const nodeWarnings = useMemo(() => {
        const m: Record<string, string[]> = {};
        for (const w of serverWarnings) {
            if (w.flow_id && w.flow_id !== activeFlow?.id) continue;
            if (w.node_id) (m[w.node_id] ??= []).push(w.message);
        }
        return m;
    }, [serverWarnings, activeFlow]);

    const activeServerWarnings = useMemo(() => {
        return serverWarnings.filter((w) => !w.flow_id || w.flow_id === activeFlow?.id);
    }, [serverWarnings, activeFlow]);

    // Issues count per flow for tabs
    const issuesByFlowId = useMemo(() => {
        const map: Record<string, number> = {};
        if (!catalog.length) return map;
        for (const f of flows) {
            const issues = validateFlowClient(f, catalog);
            if (issues.length) map[f.id] = issues.length;
        }
        return map;
    }, [flows, catalog]);

    // Save guard confirmation
    const [confirmReasons, setConfirmReasons] = useState<SaveGuardReason[]>([]);
    const [confirmOpen, setConfirmOpen] = useState(false);
    const [confirmErrors, setConfirmErrors] = useState<string[]>([]);

    const isDocDirty = docRevision > 0 && normalizedDoc(data) !== savedSnapshot;
    useBeforeUnload(isDocDirty);

    const [checkingSave, setCheckingSave] = useState(false);

    const doSave = async (opts: { quiet?: boolean } = {}) => {
        const docToSave = data ?? {version: 2, flows: [defaultEnrollmentFlow()]};
        // keepNewerEdits: an edit made while this PUT is outstanding survives it. The snapshot below records what
        // was written, so the document reads dirty and the next save converges on the newer edits.
        const ok = await save(docToSave, {...opts, keepNewerEdits: true});
        if (ok) setSavedSnapshot(normalizedDoc(docToSave));
        return ok;
    };

    const onSave = async () => {
        if (checkingSave) return;
        // Issues in a draft never block: drafts are allowed to stay unfinished, and the server accepts them as
        // warnings.
        if (!activeFlow.draft_of && clientIssues.length > 0) {
            setIssuesBlocking(true);
            setIssuesOpen(true);
            return;
        }
        setCheckingSave(true);
        try {
            const reasons: SaveGuardReason[] = [];
            const draftIds = new Set(flows.filter((f) => f.draft_of).map((f) => f.id));
            for (const f of flows) {
                // A draft never executes, so nothing about one is worth a warning.
                if (f.draft_of) continue;
                reasons.push(...saveGuardReasons(f));
            }
            const fetched = token && data ? await fetchServerVerdict(token, data) : null;
            if (fetched) {
                setServerWarnings(fetched.flowWarnings);
                setServerGateFindings(fetched.gateFindings);
                for (const w of fetched.flowWarnings) {
                    if (w.code === "release-ordering" && !(w.flow_id && draftIds.has(w.flow_id))) {
                        reasons.push({nodeId: w.node_id ?? undefined, kind: "server", message: w.message});
                    }
                }
            }
            if (reasons.length > 0) {
                setConfirmReasons(reasons);
                setConfirmErrors(fetched && !fetched.valid ? fetched.errors : []);
                setConfirmOpen(true);
                return;
            }
            if (await doSave()) {
                notifications.show({
                    color: "teal",
                    message: "Flows saved. Changes apply to devices as they enroll or check in.",
                });
            }
        } finally {
            setCheckingSave(false);
        }
    };

    const onConfirmSave = async () => {
        if (await doSave()) setConfirmOpen(false);
    };

    // Flow switcher
    const [switcherOpen, setSwitcherOpen] = useState(false);
    const [flowsSummary, setFlowsSummary] = useState<FlowsSummaryResponse | null>(null);

    const openSwitcher = () => {
        setSwitcherOpen(true);
        if (token) {
            api.getFlowsSummary(token).then(setFlowsSummary).catch(() => {
            });
        }
    };

    // New flow modal
    const [newFlowOpen, setNewFlowOpen] = useState(false);
    const [newFlowId, setNewFlowId] = useState("");
    const [newFlowName, setNewFlowName] = useState("");
    const [newFlowDesc, setNewFlowDesc] = useState("");
    // The id follows the name until the id itself is edited, after which a later name change leaves it alone.
    const [idTouched, setIdTouched] = useState(false);

    const setFlowNameAndId = (name: string) => {
        setNewFlowName(name);
        if (!idTouched) setNewFlowId(slugifyFlowId(name));
    };

    const newFlowIdIssue = useMemo(
        () => (newFlowId.trim() ? flowIdError(newFlowId.trim(), flows.map((f) => f.id)) : null),
        [newFlowId, flows],
    );

    const resetNewFlowForm = () => {
        setNewFlowOpen(false);
        setNewFlowId("");
        setNewFlowName("");
        setNewFlowDesc("");
        setIdTouched(false);
    };

    const handleCreateNewFlow = () => {
        const id = newFlowId.trim();
        const name = newFlowName.trim() || id;
        const issue = flowIdError(id, flows.map((f) => f.id));
        if (issue) {
            notifications.show({color: "red", message: issue});
            return;
        }
        const created = emptyFlow(id, name, newFlowDesc.trim());
        setData((prev) => ({
            version: 2,
            flows: [...(prev?.flows ?? flows), created],
        }));
        setOpenFlowIds((prev) => [...prev, id]);
        setActiveFlowId(id);
        resetNewFlowForm();
    };

    // How many flows differ from what is on disk. The save is whole-document and atomic, so this only labels one
    // button; there is no per-flow save.
    const dirtyFlowIds = useMemo(() => {
        if (docRevision === 0) return new Set<string>();
        const baseline = flowFingerprints(savedSnapshot);
        const ids = new Set<string>();
        for (const f of normalizeFlows(data)) {
            if (baseline.get(f.id) !== JSON.stringify(f)) ids.add(f.id);
        }
        return ids;
    }, [data, docRevision, savedSnapshot]);
    const dirtyFlowCount = dirtyFlowIds.size;

    // True when everything that differs from disk is a draft, so writing the document commits nothing the fleet can
    // see. That is the only case the editor may write on its own.
    const autosavable = useMemo(() => {
        if (!isAdmin || !dirtyFlowIds.size) return false;
        const byId = new Map(flows.map((f) => [f.id, f]));
        return [...dirtyFlowIds].every((id) => Boolean(byId.get(id)?.draft_of));
    }, [dirtyFlowIds, flows, isAdmin]);

    const [autosaveState, setAutosaveState] =
        useState<"clean" | "pending" | "saving" | "saved" | "failed">("clean");
    const [autosaveRetry, setAutosaveRetry] = useState(0);
    // The document a write already failed on. Without it a server that refuses this draft is asked again the moment
    // the save settles, forever.
    const refusedSnapshot = useRef<string | null>(null);

    useEffect(() => {
        if (!autosavable) {
            setAutosaveState((s) => (s === "failed" ? s : "clean"));
            return;
        }
        if (saving || checkingSave || confirmOpen) return;
        const snapshot = normalizedDoc(data);
        if (refusedSnapshot.current === snapshot) return;
        setAutosaveState("pending");
        const timer = window.setTimeout(async () => {
            setAutosaveState("saving");
            const ok = await doSave({quiet: true});
            refusedSnapshot.current = ok ? null : snapshot;
            setAutosaveState(ok ? "saved" : "failed");
        }, AUTOSAVE_IDLE_MS);
        return () => window.clearTimeout(timer);
        // doSave closes over this render's document, which is the one the timer must write; re-running on every edit
        // is what makes the delay a debounce.
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [autosavable, data, saving, checkingSave, confirmOpen, autosaveRetry]);

    const retryAutosave = () => {
        refusedSnapshot.current = null;
        setAutosaveRetry((n) => n + 1);
    };

    // Tab actions
    const handleSelectFlow = (id: string) => {
        if (!openFlowIds.includes(id)) {
            setOpenFlowIds((prev) => [...prev, id]);
        }
        setActiveFlowId(id);
    };

    // ?flow=<id> from the flows overview opens that flow selected, and ?new=1 opens the create dialog. Read once
    // the document has loaded, and only once: after that the tab bar owns which flow is active.
    const deepLinked = useRef(false);
    useEffect(() => {
        if (deepLinked.current || loading) return;
        deepLinked.current = true;
        const params = new URLSearchParams(window.location.search);
        if (params.has("new")) {
            setNewFlowOpen(true);
            return;
        }
        const wanted = params.get("flow");
        if (!wanted || !flows.some((f) => f.id === wanted)) return;
        setOpenFlowIds((prev) => (prev.includes(wanted) ? prev : [...prev, wanted]));
        setActiveFlowId(wanted);
    }, [loading, flows]);

    const handleCloseTab = (id: string) => {
        const nextOpen = openFlowIds.filter((fid) => fid !== id);
        setOpenFlowIds(nextOpen);
        if (activeFlowId === id) {
            setActiveFlowId(nextOpen[nextOpen.length - 1] ?? permanentFlow.id);
        }
    };

    // Draft modals and actions
    const [createDraftOpen, setCreateDraftOpen] = useState(false);
    const [createDraftNote, setCreateDraftNote] = useState("");
    const [creatingDraft, setCreatingDraft] = useState(false);

    // The same path an edit takes, asked for up front. Whatever is on the canvas goes into the draft, not a copy of
    // the file on disk.
    const handleCreateDraft = async () => {
        if (!token || !activeFlow) return;
        setCreatingDraft(true);
        try {
            await handOffToDraft(
                activeFlow,
                {nodes: activeFlow.nodes, name: activeFlow.name, description: activeFlow.description},
                createDraftNote,
            );
            setCreateDraftOpen(false);
            setCreateDraftNote("");
        } finally {
            setCreatingDraft(false);
        }
    };

    const [diffDrawerOpen, setDiffDrawerOpen] = useState(false);
    const [currentDiff, setCurrentDiff] = useState<DraftDiff | null>(null);

    const handleOpenDiff = async () => {
        if (!token || !activeFlow?.draft_of) return;
        try {
            const diff = await api.getFlowDraftDiff(token, activeFlow.draft_of);
            setCurrentDiff(diff);
            setDiffDrawerOpen(true);
        } catch (e) {
            notifications.show({color: "red", message: (e as Error).message});
        }
    };

    const [promoteModalOpen, setPromoteModalOpen] = useState(false);
    const [promoting, setPromoting] = useState(false);

    const handleOpenPromote = async () => {
        if (!token || !activeFlow?.draft_of) return;
        try {
            const diff = await api.getFlowDraftDiff(token, activeFlow.draft_of);
            setCurrentDiff(diff);
            setPromoteModalOpen(true);
        } catch (e) {
            notifications.show({color: "red", message: (e as Error).message});
        }
    };

    const handleConfirmPromote = async (options: { acknowledge: string[]; force: boolean }) => {
        if (!token || !activeFlow?.draft_of) return;
        setPromoting(true);
        try {
            const targetId = activeFlow.draft_of;
            const draftId = activeFlow.id;
            const res = await api.promoteFlowDraft(token, targetId, options, version);
            if (res.version) setVersion(res.version);
            notifications.show({color: "teal", message: `Published the draft onto ${targetId}`});
            setPromoteModalOpen(false);
            const cfg = await api.getConfigWithVersion(token, "flows");
            setData(cfg.data as FlowsConfig);
            // What came back is what is on disk, so it is also the new baseline.
            setSavedSnapshot(normalizedDoc(cfg.data as FlowsConfig));
            refusedSnapshot.current = null;
            if (cfg.version) setVersion(cfg.version);
            handleCloseTab(draftId);
            setActiveFlowId(targetId);
        } catch (e) {
            notifications.show({color: "red", message: (e as Error).message});
        } finally {
            setPromoting(false);
        }
    };

    const discardDraft = async () => {
        if (!token || !activeFlow?.draft_of) return;
        try {
            const targetId = activeFlow.draft_of;
            const draftId = activeFlow.id;
            const res = await api.discardFlowDraft(token, targetId, version);
            if (res.version) setVersion(res.version);
            setData((prev) => ({
                version: 2,
                flows: flowsFromConfig(prev).filter((f) => f.id !== draftId),
            }));
            // The server dropped it too, so the baseline drops it as well and the document does not read as changed
            // against a flow that is gone.
            setSavedSnapshot((prev) => normalizedDoc({
                version: 2,
                flows: flowsFromConfig(JSON.parse(prev || "null")).filter((f) => f.id !== draftId),
            }));
            refusedSnapshot.current = null;
            handleCloseTab(draftId);
            setActiveFlowId(targetId);
            notifications.show({color: "teal", message: `Discarded the draft of ${targetId}`});
        } catch (e) {
            notifications.show({color: "red", message: (e as Error).message});
        }
    };

    // Removing a flow removes its open draft with it: a draft of a flow that no longer exists can never be
    // promoted, and leaving it would keep a tab open on nothing.
    const handleDeleteFlow = (flow: FlowDoc) => {
        const draft = flows.find((f) => f.draft_of === flow.id);
        modals.openConfirmModal({
            title: `Delete ${flow.name || flow.id}`,
            children: (
                <Stack gap="xs">
                    <Text size="sm">
                        The flow is removed from this tenant. Devices stop starting new runs of it, and runs
                        already finished stay in the run history.
                    </Text>
                    {draft && (
                        <Text size="sm" c="orange">
                            Its open draft <b>{draft.name || draft.id}</b> goes with it.
                        </Text>
                    )}
                </Stack>
            ),
            labels: {confirm: "Delete flow", cancel: "Keep it"},
            confirmProps: {color: "red"},
            onConfirm: () => {
                const doomed = new Set([flow.id, ...(draft ? [draft.id] : [])]);
                setData((prev) => ({
                    version: 2,
                    flows: flowsFromConfig(prev).filter((f) => !doomed.has(f.id)),
                }));
                const nextOpen = openFlowIds.filter((id) => !doomed.has(id));
                setOpenFlowIds(nextOpen);
                if (doomed.has(activeFlowId)) {
                    setActiveFlowId(nextOpen[nextOpen.length - 1] ?? permanentFlow.id);
                }
            },
        });
    };

    const handleDiscardDraft = () => {
        if (!activeFlow?.draft_of) return;
        const target = activeFlow.draft_of;
        modals.openConfirmModal({
            title: "Discard this draft",
            children: (
                <Text size="sm">
                    Everything in this draft is thrown away, including the changes it saved
                    on its own. <b>{target}</b> keeps running as it is.
                </Text>
            ),
            labels: {confirm: "Discard draft", cancel: "Keep it"},
            confirmProps: {color: "red"},
            onConfirm: () => void discardDraft(),
        });
    };

    const isCurrentDraft = Boolean(activeFlow?.draft_of);
    const openDraftOfActive = flows.find((f) => f.draft_of === activeFlow?.id);
    // Something the editor may not write on its own: a live flow's switch, a flow that has just been created, a flow
    // that has been deleted.
    const liveDirty = dirtyFlowCount > 0 && !autosavable;
    // A live flow whose draft exists is read-only for admins, so the editor prevents the edit rather than undoing
    // it afterwards.
    const liveLocked = isAdmin && !isCurrentDraft && Boolean(openDraftOfActive);
    // What the indicator may claim. While the active draft holds unwritten edits it never reads as saved: stalled
    // when autosave may not write because a live flow is dirty too, pending while a write is due.
    const draftDisplayState: "clean" | "pending" | "saving" | "saved" | "failed" | "stalled" =
        !isCurrentDraft || !dirtyFlowIds.has(activeFlow.id)
            ? autosaveState
            : !autosavable
                ? "stalled"
                : autosaveState === "clean" || autosaveState === "saved"
                    ? "pending"
                    : autosaveState;

    return (
        <Stack gap={CANVAS_STACK_GAP}>
            <FlowIssuesModal
                opened={issuesOpen}
                blocking={issuesBlocking}
                flowName={activeFlow.name || activeFlow.id}
                issues={clientIssues}
                warnings={activeServerWarnings}
                onGoToNode={goToNode}
                onClose={() => setIssuesOpen(false)}
            />
            <FlowSaveConfirmModal
                flowName={activeFlow.name || activeFlow.id}
                reasons={confirmReasons}
                serverErrors={confirmErrors}
                opened={confirmOpen}
                saving={saving}
                onCancel={() => setConfirmOpen(false)}
                onConfirm={onConfirmSave}
            />
            <FlowSwitcher
                opened={switcherOpen}
                onClose={() => setSwitcherOpen(false)}
                flows={flows}
                summary={flowsSummary}
                onSelectFlow={handleSelectFlow}
                onDeleteFlow={isAdmin ? handleDeleteFlow : undefined}
                onNewFlow={() => {
                    setSwitcherOpen(false);
                    setNewFlowOpen(true);
                }}
            />
            <FlowDiff
                opened={diffDrawerOpen}
                onClose={() => setDiffDrawerOpen(false)}
                diff={currentDiff}
            />
            <PromoteDraftModal
                opened={promoteModalOpen}
                onClose={() => setPromoteModalOpen(false)}
                onPromote={handleConfirmPromote}
                diff={currentDiff}
                gateFindings={serverGateFindings.filter((f) => f.flow_id === activeFlow.id)}
                promoting={promoting}
            />

            {/* New flow modal */}
            <Modal
                opened={newFlowOpen}
                onClose={resetNewFlowForm}
                title={<Text fw={600}>New flow</Text>}
            >
                <Stack gap="sm">
                    <TextInput
                        label="Name"
                        placeholder="e.g. Daily compliance check"
                        description="What this flow is called everywhere in the console."
                        value={newFlowName}
                        onChange={(e) => setFlowNameAndId(e.currentTarget.value)}
                        data-autofocus
                        required
                    />
                    <TextInput
                        label="Flow ID"
                        placeholder="daily-compliance-check"
                        description="Written on every run this flow produces, so it cannot be changed later. Filled in from the name."
                        value={newFlowId}
                        error={newFlowIdIssue}
                        onChange={(e) => {
                            setIdTouched(true);
                            setNewFlowId(e.currentTarget.value);
                        }}
                        required
                    />
                    <Textarea
                        label="Description"
                        placeholder="What does this flow do?"
                        value={newFlowDesc}
                        onChange={(e) => setNewFlowDesc(e.currentTarget.value)}
                    />
                    <Group justify="flex-end" mt="md">
                        <Button variant="default" onClick={resetNewFlowForm}>
                            Cancel
                        </Button>
                        <Button
                            onClick={handleCreateNewFlow}
                            disabled={!newFlowName.trim() || !newFlowId.trim() || Boolean(newFlowIdIssue)}
                        >
                            Create flow
                        </Button>
                    </Group>
                </Stack>
            </Modal>

            {/* Create draft modal */}
            <Modal
                opened={createDraftOpen}
                onClose={() => setCreateDraftOpen(false)}
                title={<Text fw={600}>Create draft of {activeFlow.name || activeFlow.id}</Text>}
            >
                <Stack gap="sm">
                    <Text size="sm" c="dimmed">
                        A draft is a separate copy you can edit and review before publishing it onto the live flow.
                    </Text>
                    <Textarea
                        label="Draft note (optional)"
                        placeholder="What changes do you plan to make in this draft?"
                        value={createDraftNote}
                        onChange={(e) => setCreateDraftNote(e.currentTarget.value)}
                    />
                    <Group justify="flex-end" mt="md">
                        <Button variant="default" onClick={() => setCreateDraftOpen(false)} disabled={creatingDraft}>
                            Cancel
                        </Button>
                        <Button color="orange" onClick={handleCreateDraft} loading={creatingDraft}>
                            Create draft
                        </Button>
                    </Group>
                </Stack>
            </Modal>

            {!isAdmin && (
                <Alert color="yellow" icon={<IconInfoCircle size={16}/>}>
                    {ADMIN_ONLY_REASON} You can view flows here.
                </Alert>
            )}

            {catalogState === "error" && (
                <Alert color="red" icon={<IconAlertTriangle size={18}/>} title="Could not load node catalog">
                    The editor stays closed until the palette loads. Reload the page to try again.
                </Alert>
            )}

            {/* The toolbar floats over the canvas rather than sitting above it, so the grid and any blocks
                beneath show through its glass. */}
            <Box style={{position: "relative"}}>
                <Box style={{position: "absolute", top: 0, left: 0, right: 0, zIndex: 5}}>
                    <FlowTabs
                        flows={flows}
                        openFlowIds={openFlowIds}
                        activeFlowId={activeFlow.id}
                        onSelectFlow={handleSelectFlow}
                        onCloseTab={handleCloseTab}
                        onNewFlow={() => setNewFlowOpen(true)}
                        onOpenSwitcher={openSwitcher}
                        issuesByFlowId={issuesByFlowId}
                        dirtyFlowIds={dirtyFlowIds}
                        onCreateDraft={() => setCreateDraftOpen(true)}
                        savedFlowIds={savedFlowIds}
                        isAdmin={isAdmin}
                        adminOnlyReason={ADMIN_ONLY_REASON}
                        actions={
                            <>
                                {/* Name, id and description sit in this popover, one click from the flow they
                                describe. */}
                                <Popover width={340} position="bottom-end" withArrow shadow="md" trapFocus>
                                    <Popover.Target>
                                        <Tooltip label="Flow details" withArrow position="top">
                                            <ActionIcon size="md" variant="default">
                                                <IconInfoCircle size={16}/>
                                            </ActionIcon>
                                        </Tooltip>
                                    </Popover.Target>
                                    <Popover.Dropdown>
                                        <Stack gap="sm">
                                            <TextInput
                                                label="Name"
                                                value={activeFlow.name || ""}
                                                onChange={(e) => editActiveFlow({name: e.currentTarget.value})}
                                                disabled={!isAdmin || liveLocked}
                                            />
                                            <TextInput
                                                label="Flow ID"
                                                value={activeFlow.id}
                                                description="Written on every run this flow produced, so it cannot change."
                                                disabled
                                            />
                                            <Textarea
                                                label="Description"
                                                placeholder="What does this flow do?"
                                                value={activeFlow.description || ""}
                                                onChange={(e) => editActiveFlow({description: e.currentTarget.value})}
                                                disabled={!isAdmin || liveLocked}
                                                autosize
                                                minRows={2}
                                            />
                                            {activeFlow.permanent && !isCurrentDraft ? (
                                                <Text fz="xs" c="dimmed">
                                                    This is the permanent enrollment flow. It cannot be renamed,
                                                    deleted or switched off, and it is the only flow that may hold
                                                    Setup Assistant steps.
                                                </Text>
                                            ) : null}
                                        </Stack>
                                    </Popover.Dropdown>
                                </Popover>

                                <FlowStatusControl
                                    issues={clientIssues.length}
                                    warnings={activeServerWarnings.length}
                                    onOpen={openIssues}
                                />

                                {isCurrentDraft ? (
                                    <>
                                        <Tooltip label="Review changes against the live flow" withArrow position="top">
                                            <ActionIcon size="md" variant="default" onClick={handleOpenDiff}>
                                                <IconEye size={16}/>
                                            </ActionIcon>
                                        </Tooltip>
                                        <Button
                                            size="xs"
                                            color="green"
                                            leftSection={<IconRocket size={16}/>}
                                            onClick={handleOpenPromote}
                                            disabled={!isAdmin}
                                        >
                                            Publish
                                        </Button>
                                        <Tooltip label="Discard this draft" withArrow position="top">
                                            <ActionIcon
                                                size="md"
                                                variant="subtle"
                                                color="red"
                                                onClick={handleDiscardDraft}
                                                disabled={!isAdmin}
                                            >
                                                <IconTrash size={16}/>
                                            </ActionIcon>
                                        </Tooltip>
                                    </>
                                ) : null}

                                <Tooltip label={ADMIN_ONLY_REASON} withArrow disabled={isAdmin}>
                                    <Box>
                                        <Switch
                                            size="sm"
                                            label="Enabled"
                                            checked={activeFlow.enabled !== false}
                                            onChange={(e) => patchFlow(activeFlow.id, {enabled: e.currentTarget.checked})}
                                            disabled={!isAdmin || isCurrentDraft}
                                        />
                                    </Box>
                                </Tooltip>
                                {isCurrentDraft && (
                                    <DraftAutosaveStatus state={draftDisplayState} onRetry={retryAutosave}/>
                                )}
                                {(!isCurrentDraft || liveDirty) && (
                                    <Tooltip label={ADMIN_ONLY_REASON} withArrow disabled={isAdmin}>
                                        <Box>
                                            <Button
                                                size="xs"
                                                leftSection={<IconDeviceFloppy size={16}/>}
                                                onClick={onSave}
                                                loading={saving || checkingSave}
                                                disabled={loading || !data || !isAdmin}
                                            >
                                                {dirtyFlowCount > 1 ? `Save all (${dirtyFlowCount})` : "Save"}
                                            </Button>
                                        </Box>
                                    </Tooltip>
                                )}
                            </>
                        }
                    />

                </Box>

                <Paper
                    ref={canvasRef}
                    p={0}
                    style={{
                        height: canvasHeight,
                        minHeight: 520,
                        background: "transparent",
                        display: "flex",
                        flexDirection: "column",
                    }}
                >
                    {/* Nothing sits between the toolbar and the canvas. Draft state rides on the tab instead, so the
                        measured canvas height holds still as a draft comes and goes. */}
                    <Box style={{flex: 1, minHeight: 0}}>
                        {canvasReady ? (
                            <FlowEditor
                                // The graph on screen rather than the tab; canvasEpoch has the reason.
                                docKey={`${canvasEpoch}::${docRevision}`}
                                flowId={activeFlow.id}
                                initialNodes={activeFlow.nodes}
                                catalog={scopedCatalog}
                                options={{
                                    tagNames,
                                    profileIds,
                                    appIds,
                                    commands,
                                    groupNames: groups.map((g) => g.name),
                                    devices,
                                    allGroups: groups,
                                    startKinds: scopedStartKinds,
                                }}
                                nodeWarnings={nodeWarnings}
                                nodeIssues={nodeIssues}
                                focusNode={focusNode}
                                readOnly={liveLocked}
                                draftFlowId={liveLocked ? openDraftOfActive?.id : null}
                                onOpenDraft={handleSelectFlow}
                                onChange={onCanvasChange}
                            />
                        ) : (
                            <Center h="100%">
                                {catalogState === "error" ? (
                                    <Text c="dimmed" fz="sm">
                                        Editor unavailable.
                                    </Text>
                                ) : (
                                    <Loader/>
                                )}
                            </Center>
                        )}
                    </Box>
                </Paper>
            </Box>

        </Stack>
    );
}

/** Whether the active draft is on the server yet. It replaces the Save button on a draft tab, where there is nothing
 * left to press. A failed write is the one state here that can be clicked. */
function DraftAutosaveStatus({
                                 state,
                                 onRetry,
                             }: {
    state: "clean" | "pending" | "saving" | "saved" | "failed" | "stalled";
    onRetry: () => void;
}) {
    if (state === "failed") {
        return (
            <Tooltip label="The last write was turned down. Click to try again." withArrow>
                <Button
                    size="xs"
                    variant="light"
                    color="red"
                    leftSection={<IconCloudExclamation size={16}/>}
                    onClick={onRetry}
                >
                    Not saved
                </Button>
            </Tooltip>
        );
    }
    if (state === "stalled") {
        // Autosave is parked because a live flow is dirty too. Only the Save button writes now, and the indicator
        // must not claim otherwise.
        return (
            <Tooltip label="Save writes everything, including this draft." withArrow>
                <Group gap={6} c="orange" wrap="nowrap">
                    <IconCloudPause size={16}/>
                    <Text fz="xs">Not saved yet</Text>
                </Group>
            </Tooltip>
        );
    }
    const busy = state === "pending" || state === "saving";
    return (
        <Tooltip
            label={busy ? "Writing this draft to the server" : "This draft is saved. Publish to make it live."}
            withArrow
        >
            <Group gap={6} c="dimmed" wrap="nowrap">
                {busy ? <Loader size={14}/> : <IconCloudCheck size={16}/>}
                <Text fz="xs">{busy ? "Saving" : "Draft saved"}</Text>
            </Group>
        </Tooltip>
    );
}

function FlowStatusControl({
                               issues,
                               warnings,
                               onOpen,
                           }: {
    issues: number;
    warnings: number;
    onOpen: () => void;
}) {
    if (issues > 0) {
        return (
            <Tooltip label="Blocks that are not finished yet. Click for the list." withArrow>
                <Button
                    variant="light"
                    color="red"
                    leftSection={<IconExclamationCircle size={16}/>}
                    onClick={onOpen}
                >
                    {issues} {issues === 1 ? "issue" : "issues"}
                </Button>
            </Tooltip>
        );
    }
    if (warnings > 0) {
        return (
            <Tooltip label="Advisory, from the server. Click for the list." withArrow>
                <Button
                    variant="light"
                    color="yellow"
                    leftSection={<IconAlertTriangle size={16}/>}
                    onClick={onOpen}
                >
                    {warnings} {warnings === 1 ? "warning" : "warnings"}
                </Button>
            </Tooltip>
        );
    }
    return (
        <Group gap={6} c="dimmed" wrap="nowrap" align="center">
            <IconCircleCheck size={16}/>
            <Text fz="sm">No issues</Text>
        </Group>
    );
}
