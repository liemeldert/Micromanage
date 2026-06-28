"use client";

import { useEffect, useMemo, useState } from "react";
import {
  Badge,
  Box,
  Button,
  FileButton,
  Group,
  JsonInput,
  MultiSelect,
  NumberInput,
  PasswordInput,
  Select,
  Stack,
  Switch,
  TagsInput,
  Text,
  Textarea,
  TextInput,
} from "@mantine/core";
import { IconSearch, IconUpload } from "@tabler/icons-react";
import {
  fieldSupportsPlatforms,
  type ManifestField,
  type PayloadManifest,
  type Platform,
} from "../../../lib/profile-manifests";

async function fileToBase64(file: File | null): Promise<string | null> {
  if (!file) return null;
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function StructuredField({
  field,
  value,
  label,
  onCommit,
}: {
  field: ManifestField;
  value: unknown;
  label: React.ReactNode;
  onCommit: (v: unknown) => void;
}) {
  const [text, setText] = useState(() =>
    value === undefined ? (field.type === "array" ? "[]" : "{}") : JSON.stringify(value, null, 2),
  );

  useEffect(() => {
    setText(
      value === undefined ? (field.type === "array" ? "[]" : "{}") : JSON.stringify(value, null, 2),
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [field.name]);

  return (
    <JsonInput
      label={label}
      description={field.description}
      value={text}
      onChange={(t) => {
        setText(t);
        try {
          onCommit(t.trim() ? JSON.parse(t) : undefined);
        } catch {
          /* keep typing */
        }
      }}
      validationError="Invalid JSON"
      formatOnBlur
      autosize
      minRows={3}
      styles={{ input: { fontFamily: "var(--mantine-font-family-monospace)", fontSize: 12 } }}
    />
  );
}

export function PayloadForm({
  manifest,
  value,
  onChange,
  platforms,
}: {
  manifest: PayloadManifest;
  value: Record<string, unknown>;
  onChange: (next: Record<string, unknown>) => void;
  platforms?: Platform[];
}) {
  const [query, setQuery] = useState("");

  function rawValue(field: ManifestField): unknown {
    if (field.parent) {
      const container = value[field.parent] as Record<string, unknown> | undefined;
      return container?.[field.name];
    }
    return value[field.name];
  }

  function current(field: ManifestField): unknown {
    const r = rawValue(field);
    return r !== undefined ? r : field.default;
  }

  function setField(field: ManifestField, v: unknown) {
    const empty = v === undefined || v === null || v === "";
    const next = { ...value };
    if (field.parent) {
      const container = { ...((next[field.parent] as Record<string, unknown>) ?? {}) };
      if (empty) delete container[field.name];
      else container[field.name] = v;
      if (Object.keys(container).length) next[field.parent] = container;
      else delete next[field.parent];
    } else if (empty) {
      delete next[field.name];
    } else {
      next[field.name] = v;
    }
    if (!manifest.domain.startsWith("__")) next.PayloadType = manifest.domain;
    onChange(next);
  }

  const platformFields = useMemo(
    () => manifest.fields.filter((f) => fieldSupportsPlatforms(f, platforms)),
    [manifest, platforms],
  );
  const fields = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return platformFields;
    return platformFields.filter((f) => `${f.title} ${f.name}`.toLowerCase().includes(q));
  }, [platformFields, query]);

  function labelNode(field: ManifestField): React.ReactNode {
    const platformSpecific =
      field.platforms && field.platforms.length > 0 && field.platforms.length < manifest.platforms.length;
    if (!field.supervised && !platformSpecific) return field.title;
    return (
      <Group gap={6} component="span" wrap="nowrap" style={{ display: "inline-flex" }}>
        <span>{field.title}</span>
        {field.supervised && (
          <Badge size="xs" color="orange" variant="light">
            supervised
          </Badge>
        )}
        {platformSpecific &&
          field.platforms!.map((p) => (
            <Badge key={p} size="xs" color="gray" variant="outline">
              {p}
            </Badge>
          ))}
      </Group>
    );
  }

  return (
    <Stack gap="sm">
      {platformFields.length > 12 && (
        <TextInput
          placeholder={`Search ${platformFields.length} keys…`}
          leftSection={<IconSearch size={14} />}
          value={query}
          onChange={(e) => setQuery(e.currentTarget.value)}
          size="xs"
        />
      )}

      {fields.map((field) => {
        const val = current(field);
        const label = labelNode(field);

        if (field.type === "boolean") {
          return (
            <Switch
              key={field.name}
              label={label}
              description={field.description}
              checked={!!val}
              onChange={(e) => setField(field, e.currentTarget.checked)}
            />
          );
        }

        if (field.type === "string" && field.options) {
          return (
            <Select
              key={field.name}
              label={label}
              description={field.description}
              data={field.options.map((o) => ({ value: o, label: field.optionLabels?.[o] ?? o }))}
              value={(val as string) ?? null}
              onChange={(v) => setField(field, v)}
              withAsterisk={field.required}
              clearable={!field.required}
              comboboxProps={{ withinPortal: true }}
            />
          );
        }

        if (field.type === "array" && field.options) {
          return (
            <MultiSelect
              key={field.name}
              label={label}
              description={field.description}
              data={field.options}
              value={Array.isArray(val) ? (val as string[]) : []}
              onChange={(v) => setField(field, v.length ? v : undefined)}
              searchable
              clearable
              comboboxProps={{ withinPortal: true }}
            />
          );
        }

        if (field.type === "array") {
          return (
            <TagsInput
              key={field.name}
              label={label}
              description={field.description}
              placeholder="Add values, press Enter"
              value={Array.isArray(val) ? (val as string[]) : []}
              onChange={(v) => setField(field, v.length ? v : undefined)}
            />
          );
        }

        if (field.type === "string" && field.secret) {
          return (
            <PasswordInput
              key={field.name}
              label={label}
              description={field.description}
              value={(val as string) ?? ""}
              onChange={(e) => setField(field, e.currentTarget.value)}
              withAsterisk={field.required}
            />
          );
        }

        if (field.type === "string") {
          return (
            <TextInput
              key={field.name}
              label={label}
              description={field.description}
              value={(val as string) ?? ""}
              onChange={(e) => setField(field, e.currentTarget.value)}
              withAsterisk={field.required}
            />
          );
        }

        if (field.type === "integer" || field.type === "real") {
          return (
            <NumberInput
              key={field.name}
              label={label}
              description={field.description}
              min={field.min}
              max={field.max}
              allowDecimal={field.type === "real"}
              value={(val as number) ?? ""}
              onChange={(v) => setField(field, v === "" || v === undefined ? undefined : Number(v))}
              withAsterisk={field.required}
            />
          );
        }

        if (field.type === "data") {
          return (
            <Box key={field.name}>
              <Group justify="space-between" align="center" mb={4}>
                <Text fz="sm" fw={500} component="div">
                  {label}
                </Text>
                <FileButton onChange={(f) => fileToBase64(f).then((b) => b && setField(field, b))}>
                  {(props) => (
                    <Button {...props} size="compact-xs" variant="light" leftSection={<IconUpload size={12} />}>
                      Upload file
                    </Button>
                  )}
                </FileButton>
              </Group>
              {field.description && (
                <Text fz="xs" c="dimmed" mb={4}>
                  {field.description}
                </Text>
              )}
              <Textarea
                placeholder="base64…"
                autosize
                minRows={2}
                maxRows={6}
                value={(val as string) ?? ""}
                onChange={(e) => setField(field, e.currentTarget.value)}
                styles={{ input: { fontFamily: "var(--mantine-font-family-monospace)", fontSize: 12 } }}
              />
            </Box>
          );
        }

        return (
          <StructuredField
            key={field.name}
            field={field}
            label={label}
            value={rawValue(field)}
            onCommit={(v) => setField(field, v)}
          />
        );
      })}

      {fields.length === 0 && (
        <Text fz="sm" c="dimmed" ta="center" py="md">
          No keys match.
        </Text>
      )}

      <Text fz="xs" c="dimmed">
        {query ? `${fields.length} of ${platformFields.length} keys` : `${platformFields.length} keys`} ·
        empty fields are omitted (device uses Apple&apos;s default).
      </Text>
    </Stack>
  );
}
