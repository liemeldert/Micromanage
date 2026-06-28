"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import {
  Box,
  Button,
  Center,
  Paper,
  PasswordInput,
  Stack,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import { useForm } from "@mantine/form";
import { notifications } from "@mantine/notifications";
import { useAuth } from "../../../lib/auth-context";
import { ApiError } from "../../../lib/api";

export default function LoginPage() {
  const { login } = useAuth();
  const router = useRouter();
  const [loading, setLoading] = useState(false);

  const form = useForm({
    initialValues: { tenantId: "default", email: "", password: "" },
    validate: {
      tenantId: (v) => (v.trim() ? null : "Tenant ID required"),
      email: (v) => (/\S+@\S+\.\S+/.test(v) ? null : "Valid email required"),
      password: (v) => (v ? null : "Password required"),
    },
  });

  const handleSubmit = async (values: typeof form.values) => {
    setLoading(true);
    try {
      await login(values.tenantId.trim(), values.email.trim(), values.password);
      router.push("/dashboard");
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : "Login failed";
      notifications.show({ color: "red", title: "Authentication failed", message: msg });
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box
      style={{
        minHeight: "100vh",
        background: "var(--mantine-color-dark-8, #1a1b1e)",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
      }}
    >
      <Center>
        <Stack align="center" gap="xl">
          <Stack align="center" gap="xs">
            <Title order={1} c="white" fw={700} fz={32}>
              MicromanageIAC
            </Title>
            <Text c="dimmed" fz="sm">
              YAML-driven Apple MDM compliance controller
            </Text>
          </Stack>

          <Paper shadow="xl" p="xl" radius="md" w={400}>
            <form onSubmit={form.onSubmit(handleSubmit)}>
              <Stack gap="md">
                <Title order={3} fw={600}>
                  Sign in
                </Title>

                <TextInput
                  label="Tenant ID"
                  placeholder="default"
                  {...form.getInputProps("tenantId")}
                />

                <TextInput
                  label="Email address"
                  placeholder="you@example.com"
                  {...form.getInputProps("email")}
                />

                <PasswordInput
                  label="Password"
                  placeholder="Your password"
                  {...form.getInputProps("password")}
                />

                <Button type="submit" loading={loading} fullWidth mt="xs">
                  Sign in
                </Button>
              </Stack>
            </form>
          </Paper>
        </Stack>
      </Center>
    </Box>
  );
}
