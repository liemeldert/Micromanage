"use client";

// The tenant's declarative config, as the controller holds it on disk. Groups, apps and profiles are editable here:
// the draft is parsed in the browser, validated server-side before it is written, and a save triggers reconciliation.

import {Suspense, useCallback, useEffect, useRef, useState} from "react";
import {useSearchParams} from "next/navigation";
import {Alert, Badge, Box, Button, FileButton, List, Loader, Stack, Tabs, Text, Textarea,} from "@mantine/core";
import {CodeHighlight} from "@mantine/code-highlight";
import {modals} from "@mantine/modals";
import {notifications} from "@mantine/notifications";
import yaml from "js-yaml";
import {
    IconAlertTriangle,
    IconApps,
    IconChecks,
    IconCircleCheck,
    IconDeviceFloppy,
    IconDownload,
    IconEdit,
    IconFileCertificate,
    IconFileDescription,
    IconHistory,
    IconInfoCircle,
    IconRefresh,
    IconStack2,
    IconUpload,
    IconX,
} from "@tabler/icons-react";
import {api, ApiError, configConflict} from "../../../../lib/api";
import {useAuth} from "../../../../lib/auth-context";
import {showConfigConflict} from "../../../../lib/config";
import {saveTextFile} from "../../../../lib/download";
import {ConfigHistoryDrawer} from "@/components/config/ConfigHistoryDrawer";
import {PageHeader} from "@/components/layout/PageHeader";

type ConfigType = "profiles" | "groups" | "apps" | "declarations" | "config";
type EditableType = Exclude<ConfigType, "config">;

const TABS: { value: ConfigType; label: string; icon: React.FC<{ size?: number }> }[] = [
    {value: "profiles", label: "profiles.yaml", icon: IconFileCertificate},
    {value: "groups", label: "groups.yaml", icon: IconStack2},
    {value: "apps", label: "apps.yaml", icon: IconApps},
    {value: "declarations", label: "declarations.yaml", icon: IconFileDescription},
    // { value: "config",   label: "config.yaml",   icon: IconSettings }, // I see no need for this to be user-accessible at the moment.
];

const EDITABLE: ConfigType[] = ["profiles", "groups", "apps", "declarations"];

function isConfigType(v: string | null): v is ConfigType {
    return !!v && TABS.some((t) => t.value === v);
}

export default function YamlPage() {
    return (
        // useSearchParams requires a Suspense boundary during prerender.
        <Suspense fallback={null}>
            <YamlPageInner/>
        </Suspense>
    );
}

// Saving any document on this page is admin-only, so a member's save 403s. Reading is not, and profiles come back
// with their secrets redacted, so members get the viewer without the editor.
const ADMIN_ONLY_REASON =
    "These documents decide what every managed device gets, so editing them is admin-only.";

function YamlPageInner() {
    const {token, isAdmin} = useAuth();
    const searchParams = useSearchParams();
    const initialType = searchParams.get("type");
    const [active, setActive] = useState<ConfigType>(
        isConfigType(initialType) ? initialType : "profiles",
    );
    const [docs, setDocs] = useState<Partial<Record<ConfigType, string | null>>>({});
    // Version of each loaded document, sent back as If-Match so a save cannot silently overwrite someone else's.
    const [versions, setVersions] = useState<Partial<Record<ConfigType, string>>>({});
    const [loading, setLoading] = useState(false);
    const [editing, setEditing] = useState(false);
    const [draft, setDraft] = useState("");
    // The text the editor opened on, so Cancel knows whether anything was typed.
    const [baseline, setBaseline] = useState("");
    const [saving, setSaving] = useState(false);
    const [parseError, setParseError] = useState<string | null>(null);
    // Last answer from the dry-run PUT, for the draft as it stood when Validate was pressed. Cleared on every
    // keystroke, so a stale verdict never sits under text it was not computed for.
    const [validation, setValidation] =
        useState<{ valid: boolean; errors: string[]; warnings: string[] } | null>(null);
    const [validating, setValidating] = useState(false);
    const [historyOpen, setHistoryOpen] = useState(false);
    const resetRef = useRef<() => void>(null);

    // The in-app discard confirmation only covers the Cancel button and the tab switcher, so a reload or a closed
    // tab would drop the buffer without a word. Same dirty condition cancelEditing uses.
    useEffect(() => {
        if (!editing || draft === baseline) return;
        const handler = (e: BeforeUnloadEvent) => {
            e.preventDefault();
            e.returnValue = "";
        };
        window.addEventListener("beforeunload", handler);
        return () => window.removeEventListener("beforeunload", handler);
    }, [editing, draft, baseline]);

    // Returns the document text, null when there is no file, so a caller putting it back in the editor does not race
    // the state update.
    const load = useCallback(async (type: ConfigType, force = false) => {
        if (!token) return null;
        if (!force && docs[type] !== undefined) return docs[type] ?? null; // cached for this visit
        setLoading(true);
        try {
            const {text, version} = await api.getConfigRaw(token, type);
            setDocs((d) => ({...d, [type]: text}));
            setVersions((v) => ({...v, [type]: version}));
            return text;
        } catch (e: unknown) {
            if (e instanceof ApiError && e.status === 404) {
                setDocs((d) => ({...d, [type]: null})); // no file yet
                setVersions((v) => ({...v, [type]: undefined}));
            } else {
                notifications.show({color: "red", message: (e as Error).message});
            }
            return null;
        } finally {
            setLoading(false);
        }
    }, [token, docs]);

    useEffect(() => {
        load(active);
    }, [active, load]);

    const doc = docs[active];
    const editable = EDITABLE.includes(active) && isAdmin;

    const startEditing = () => {
        // Editing an absent file starts from the minimal valid document.
        const start = doc ?? `${active}: []\n`;
        setDraft(start);
        setBaseline(start);
        setParseError(null);
        setValidation(null);
        setEditing(true);
    };

    const discardEditing = () => {
        setEditing(false);
        setDraft("");
        setBaseline("");
        setParseError(null);
        setValidation(null);
    };

    const cancelEditing = () => {
        // Leaving edit mode throws the buffer away, so a changed one asks first.
        if (draft === baseline) {
            discardEditing();
            return;
        }
        modals.openConfirmModal({
            title: "Discard your edits?",
            children: (
                <Text size="sm">
                    Your changes to <b>{active}.yaml</b> have not been saved. Leaving the editor throws
                    them away and there is no undo.
                </Text>
            ),
            labels: {confirm: "Discard edits", cancel: "Keep editing"},
            confirmProps: {color: "red"},
            onConfirm: discardEditing,
        });
    };

    const validateDraft = (text: string): Record<string, unknown> | null => {
        try {
            const parsed = yaml.load(text);
            if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
                setParseError(`Document must be a mapping with a top-level "${active}:" key`);
                return null;
            }
            if (!(active in (parsed as Record<string, unknown>))) {
                setParseError(`Missing top-level "${active}:" key`);
                return null;
            }
            setParseError(null);
            return parsed as Record<string, unknown>;
        } catch (e) {
            setParseError((e as Error).message);
            return null;
        }
    };

    // The same PUT the save makes, in the server's dry-run mode: errors and warnings come back and nothing is
    // written. Nothing is checked here beyond the parse.
    const handleValidate = async () => {
        if (!token) return;
        const parsed = validateDraft(draft);
        // A document the YAML parser rejects has nothing to send, and the parse error is already on screen.
        if (!parsed) {
            setValidation(null);
            return;
        }
        setValidating(true);
        try {
            const res = await api.validateConfig(token, active as EditableType, parsed);
            setValidation({
                valid: res.valid,
                errors: res.errors ?? [],
                warnings: res.warnings ?? [],
            });
        } catch (e) {
            setValidation(null);
            notifications.show({
                color: "red",
                title: "Could not validate",
                message: (e as Error).message,
            });
        } finally {
            setValidating(false);
        }
    };

    // Someone else saved this document mid-edit. Their version replaces the buffer, losing the typed edits, since
    // the two cannot both be written.
    const reloadAfterConflict = async () => {
        const text = await load(active, true);
        if (!editing) return;
        const start = text ?? `${active}: []\n`;
        setDraft(start);
        setBaseline(start);
        setParseError(null);
        setValidation(null);
    };

    const handleSave = async () => {
        if (!token) return;
        const parsed = validateDraft(draft);
        if (!parsed) return;
        setSaving(true);
        try {
            // The server re-validates and, on success, reconciles devices against the new declared state. The raw
            // draft goes alongside the parsed structure so the document's comments survive the save.
            const res = await api.updateConfig(token, active as EditableType, parsed, draft,
                {ifMatch: versions[active]});
            notifications.show({
                color: "teal",
                title: "Saved",
                message: res.warnings?.length ? `Warnings: ${res.warnings.join("; ")}` : res.message,
            });
            setEditing(false);
            setBaseline("");
            setValidation(null);
            await load(active, true);
        } catch (e) {
            const conflict = configConflict(e);
            if (conflict) {
                showConfigConflict(
                    `${conflict.message} Reloading replaces what you typed.`,
                    reloadAfterConflict,
                );
                return;
            }
            notifications.show({
                color: "red",
                title: "Validation failed",
                message: (e as Error).message,
                autoClose: 8000,
            });
        } finally {
            setSaving(false);
        }
    };

    const handleExport = () => {
        saveTextFile(`${active}.yaml`, editing ? draft : (doc ?? ""), "text/yaml");
    };

    const handleImport = async (file: File | null) => {
        resetRef.current?.();
        if (!file) return;
        const text = await file.text();
        setDraft(text);
        // The file is an unsaved edit like any other, so Cancel compares it with what is on the server.
        setBaseline(doc ?? `${active}: []\n`);
        setParseError(null);
        setValidation(null);
        setEditing(true);
        validateDraft(text);
        notifications.show({
            color: "blue",
            message: `Loaded ${file.name} into the editor. Review and save to apply.`,
        });
    };

    return (
        <Stack gap="lg">
            <PageHeader
                actions={<>
                    {editable && !editing && (
                        <>
                            <Button
                                variant="light"
                                leftSection={<IconHistory size={14}/>}
                                onClick={() => setHistoryOpen(true)}
                            >
                                History
                            </Button>
                            <FileButton onChange={handleImport} accept=".yaml,.yml" resetRef={resetRef}>
                                {(props) => (
                                    <Button {...props} variant="light" leftSection={<IconUpload size={14}/>}>
                                        Import
                                    </Button>
                                )}
                            </FileButton>
                            <Button variant="light" leftSection={<IconEdit size={14}/>} onClick={startEditing}>
                                Edit
                            </Button>
                        </>
                    )}
                    {editing && (
                        <>
                            <Button
                                variant="light"
                                leftSection={<IconChecks size={14}/>}
                                loading={validating}
                                disabled={!!parseError || saving}
                                onClick={handleValidate}
                            >
                                Validate
                            </Button>
                            <Button
                                color="teal"
                                leftSection={<IconDeviceFloppy size={14}/>}
                                loading={saving}
                                disabled={!!parseError}
                                onClick={handleSave}
                            >
                                Save & apply
                            </Button>
                            <Button variant="subtle" color="gray" leftSection={<IconX size={14}/>}
                                    onClick={cancelEditing}>
                                Cancel
                            </Button>
                        </>
                    )}
                    <Button variant="light" leftSection={<IconDownload size={14}/>} onClick={handleExport}>
                        Export
                    </Button>
                    {!editing && (
                        <Button variant="light" leftSection={<IconRefresh size={14}/>}
                                onClick={() => load(active, true)}>
                            Refresh
                        </Button>
                    )}
                </>}
            />
            {editing && <Badge color="orange" variant="light">editing {active}.yaml</Badge>}

            {!isAdmin && (
                <Alert color="yellow" variant="light" icon={<IconInfoCircle size={14}/>}>
                    {ADMIN_ONLY_REASON} You can read them here; profile payload secrets are redacted.
                </Alert>
            )}

            <Alert icon={<IconInfoCircle size={14}/>} color="blue" variant="light">
                This is the declarative state the controller reconciles devices against.
                Saving here validates the document server-side and immediately queues the
                resulting device tasks.

                Double-check your edits before saving. They take effect right away and can disrupt active devices if
                something is wrong.
            </Alert>

            <Tabs
                value={active}
                onChange={(v) => {
                    if (editing) {
                        notifications.show({color: "orange", message: "Save or cancel your edits first."});
                        return;
                    }
                    setActive((v as ConfigType) ?? "profiles");
                }}
            >
                <Tabs.List>
                    {TABS.map((t) => (
                        <Tabs.Tab key={t.value} value={t.value} leftSection={<t.icon size={14}/>}>
                            {t.label}
                        </Tabs.Tab>
                    ))}
                </Tabs.List>
            </Tabs>

            {editing ? (
                <Stack gap="xs">
                    {parseError && (
                        <Alert color="red" variant="light" title="YAML error">
                            <Text fz="xs" style={{fontFamily: "monospace", whiteSpace: "pre-wrap"}}>
                                {parseError}
                            </Text>
                        </Alert>
                    )}
                    {/* Errors and warnings render separately: errors are what the server refuses,
                        warnings are what it accepts anyway. */}
                    {validation && validation.errors.length > 0 && (
                        <Alert
                            color="red"
                            variant="light"
                            title={`The server will reject this document: ${validation.errors.length} error${validation.errors.length === 1 ? "" : "s"}`}
                        >
                            <List size="sm">
                                {validation.errors.map((e, i) => (
                                    <List.Item key={`err-${i}`}>{e}</List.Item>
                                ))}
                            </List>
                        </Alert>
                    )}
                    {validation && validation.warnings.length > 0 && (
                        <Alert
                            color="yellow"
                            variant="light"
                            icon={<IconAlertTriangle size={18}/>}
                            title={`${validation.warnings.length} warning${validation.warnings.length === 1 ? "" : "s"} about this document`}
                        >
                            <List size="sm">
                                {validation.warnings.map((w, i) => (
                                    <List.Item key={`warn-${i}`}>{w}</List.Item>
                                ))}
                            </List>
                            <Text fz="xs" c="dimmed" mt={6}>
                                Warnings never block a save. They come from the server and refresh every time
                                you validate.
                            </Text>
                        </Alert>
                    )}
                    {validation && validation.valid && !validation.errors.length && !validation.warnings.length && (
                        <Alert
                            color="teal"
                            variant="light"
                            icon={<IconCircleCheck size={18}/>}
                            title="No problems found"
                        >
                            <Text fz="sm">
                                The server checked this document against the other configuration files and had
                                nothing to report. Nothing was written.
                            </Text>
                        </Alert>
                    )}
                    <Textarea
                        value={draft}
                        onChange={(e) => {
                            setDraft(e.currentTarget.value);
                            // The verdict belongs to the text it was computed for.
                            if (validation) setValidation(null);
                            if (parseError) validateDraft(e.currentTarget.value);
                        }}
                        onBlur={() => validateDraft(draft)}
                        autosize
                        minRows={16}
                        maxRows={32}
                        styles={{
                            input: {fontFamily: "var(--mantine-font-family-monospace)", fontSize: 13},
                        }}
                        spellCheck={false}
                    />
                </Stack>
            ) : loading && doc === undefined ? (
                <Box py={60} style={{textAlign: "center"}}><Loader/></Box>
            ) : doc === null ? (
                <Stack align="center" py="xl" gap="sm">
                    <Text c="dimmed">
                        No {active}.yaml yet. It gets created the first time you save.
                    </Text>
                    {editable && (
                        <Button variant="light" leftSection={<IconEdit size={14}/>} onClick={startEditing}>
                            Create it now
                        </Button>
                    )}
                </Stack>
            ) : (
                <CodeHighlight
                    code={doc ?? ""}
                    language="yaml"
                    withBorder
                    style={{maxHeight: "70vh", overflow: "auto"}}
                />
            )}

            {editable && (
                <ConfigHistoryDrawer
                    opened={historyOpen}
                    onClose={() => setHistoryOpen(false)}
                    type={active as EditableType}
                    currentDoc={doc ?? ""}
                    currentVersion={versions[active]}
                    onRestored={() => load(active, true)}
                />
            )}
        </Stack>
    );
}
