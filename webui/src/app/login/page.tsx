"use client";

// Email-first sign-in. Step 1 asks only for the email; the controller's
// discovery endpoint (rate-limited) says which tenants that email can sign in
// to and how (local password vs external IdP). Single local tenant → straight
// to password. Several tenants → picker. External IdP → hand off to the
// provider's configured sign-in page.

import { Suspense, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  Alert,
  Anchor,
  Box,
  Button,
  Center,
  Group,
  Paper,
  PasswordInput,
  Radio,
  Stack,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { IconArrowLeft, IconClockExclamation, IconExternalLink } from "@tabler/icons-react";
import { useAuth } from "../../../lib/auth-context";
import { api, ApiError, type DiscoveredTenant } from "../../../lib/api";

type Step = "email" | "tenant" | "password" | "external";

function LoginFlow() {
  const { login } = useAuth();
  const router = useRouter();
  const searchParams = useSearchParams();
  const expired = searchParams.get("expired") === "1";

  const [step, setStep] = useState<Step>("email");
  const [loading, setLoading] = useState(false);
  const [email, setEmail] = useState("");
  const [tenants, setTenants] = useState<DiscoveredTenant[]>([]);
  const [selected, setSelected] = useState<DiscoveredTenant | null>(null);
  const [manualTenant, setManualTenant] = useState("default");
  const [password, setPassword] = useState("");

  const emailValid = /\S+@\S+\.\S+/.test(email);

  // After a tenant is chosen / discovered, route to the right step.
  const proceedWith = (t: DiscoveredTenant | null) => {
    setSelected(t);
    if (t && t.provider !== "local") setStep("external");
    else setStep("password");
  };

  const handleEmailSubmit = async () => {
    if (!emailValid) return;
    setLoading(true);
    try {
      const res = await api.discoverLogin(email.trim());
      setTenants(res.tenants);
      if (res.tenants.length === 1) proceedWith(res.tenants[0]);
      else if (res.tenants.length > 1) setStep("tenant");
      // Unknown email: continue to the password step with a manual tenant
      // field -- the final sign-in gives the same generic error either way.
      else proceedWith(null);
    } catch (e) {
      const msg =
        e instanceof ApiError && e.status === 429
          ? "Too many attempts! Slow down! Please wait a minute and try again."
          : (e as Error).message;
      notifications.show({ color: "red", message: msg });
    } finally {
      setLoading(false);
    }
  };

  const handlePasswordSubmit = async () => {
    if (!password) return;
    setLoading(true);
    try {
      const tenantId = selected?.tenant_id ?? manualTenant.trim();
      await login(tenantId, email.trim(), password);
      router.push("/dashboard");
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : "Login failed";
      notifications.show({ color: "red", title: "Authentication failed", message: msg });
    } finally {
      setLoading(false);
    }
  };

  const back = () => {
    setPassword("");
    setSelected(null);
    // From password/external, step back to the tenant picker if there was a
    // real choice; otherwise all the way to the email step.
    if ((step === "password" || step === "external") && tenants.length > 1) {
      setStep("tenant");
    } else {
      setStep("email");
    }
  };

  return (
    <Paper shadow="xl" p="xl" radius="md" w={400}>
      <Stack gap="md">
        <Title order={3} fw={600}>Sign in</Title>

        {expired && step === "email" && (
          <Alert color="yellow" icon={<IconClockExclamation size={16} />} variant="light">
            Your session has expired. Please sign in again.
          </Alert>
        )}

        {step === "email" && (
          <form onSubmit={(e) => { e.preventDefault(); handleEmailSubmit(); }}>
            <Stack gap="md">
              <TextInput
                label="Email address"
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.currentTarget.value)}
                error={email && !emailValid ? "Valid email required" : null}
                autoFocus
                data-autofocus
              />
              <Button type="submit" loading={loading} disabled={!emailValid} fullWidth>
                Continue
              </Button>
            </Stack>
          </form>
        )}

        {step === "tenant" && (
          <Stack gap="md">
            <Text fz="sm" c="dimmed">
              <Text span fw={600}>{email}</Text> has access to several organizations:
            </Text>
            <Radio.Group
              value={selected?.tenant_id ?? ""}
              onChange={(v) => setSelected(tenants.find((t) => t.tenant_id === v) ?? null)}
            >
              <Stack gap="xs">
                {tenants.map((t) => (
                  <Radio
                    key={t.tenant_id}
                    value={t.tenant_id}
                    label={
                      <Group gap={6}>
                        <Text fz="sm">{t.name}</Text>
                        <Text fz="xs" c="dimmed">
                          ({t.provider === "local" ? "password" : t.provider})
                        </Text>
                      </Group>
                    }
                  />
                ))}
              </Stack>
            </Radio.Group>
            <Button
              onClick={() => selected && proceedWith(selected)}
              disabled={!selected}
              fullWidth
            >
              Continue
            </Button>
            <Anchor fz="xs" onClick={back} c="dimmed">
              <Group gap={4}><IconArrowLeft size={12} /> Use a different email</Group>
            </Anchor>
          </Stack>
        )}

        {step === "password" && (
          <form onSubmit={(e) => { e.preventDefault(); handlePasswordSubmit(); }}>
            <Stack gap="md">
              <Text fz="sm" c="dimmed">
                Signing in as <Text span fw={600}>{email}</Text>
                {selected ? <> to <Text span fw={600}>{selected.name}</Text></> : null}
              </Text>
              {!selected && (
                <TextInput
                  label="Tenant ID"
                  description="Your organization's tenant identifier"
                  value={manualTenant}
                  onChange={(e) => setManualTenant(e.currentTarget.value)}
                />
              )}
              <PasswordInput
                label="Password"
                placeholder="Your password"
                value={password}
                onChange={(e) => setPassword(e.currentTarget.value)}
                autoFocus
                data-autofocus
              />
              <Button type="submit" loading={loading} disabled={!password} fullWidth>
                Sign in
              </Button>
              <Anchor fz="xs" onClick={back} c="dimmed">
                <Group gap={4}><IconArrowLeft size={12} /> Back</Group>
              </Anchor>
            </Stack>
          </form>
        )}

        {step === "external" && selected && (
          <Stack gap="md">
            <Alert color="blue" variant="light">
              <Text fz="sm">
                <Text span fw={600}>{selected.name}</Text> uses{" "}
                <Text span fw={600}>{selected.provider}</Text> for sign-in.
              </Text>
            </Alert>
            {selected.login_url ? (
              <Button
                component="a"
                href={selected.login_url}
                rightSection={<IconExternalLink size={14} />}
                fullWidth
              >
                Continue to identity provider
              </Button>
            ) : (
              <Text fz="sm" c="dimmed">
                Sign in through your organization&apos;s identity provider, then return.
                Contact your administrator if you don&apos;t have access.
              </Text>
            )}
            <Anchor fz="xs" onClick={back} c="dimmed">
              <Group gap={4}><IconArrowLeft size={12} /> Back</Group>
            </Anchor>
          </Stack>
        )}
      </Stack>
    </Paper>
  );
}

export default function LoginPage() {
  return (
    <Box
      style={{
        minHeight: "100vh",
        background: "var(--mantine-color-gray-2)",
        display: "flex",
        flexDirection: "column",
      }}
    >
      <Box p="lg">
        <Stack gap={4}>
          <Title order={1} c="white" fw={700} fz={32} style={{
                background: "linear-gradient(to left, #7928CA, #FF0080)",
                WebkitBackgroundClip: "text",
                WebkitTextFillColor: "transparent",
                backgroundClip: "text",
              }}>
              Micromanage
            </Title>
          <Text c="black" fz="sm">
            Open device management platform.
          </Text>
        </Stack>
      </Box>
      <Box
        style={{
          flex: 1,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <Stack align="center" gap="md" style={{ width: 400 }}>
          {/* useSearchParams requires a Suspense boundary during prerender */}
          <Suspense fallback={null}>
            <LoginFlow />
          </Suspense>
        </Stack>
      </Box>
    </Box>
  );
}
