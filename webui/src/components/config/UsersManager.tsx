"use client";

// Admin console for tenant users (controller/api/main.py user endpoints).
// Unlike the YAML-backed config editors (tags/apps/etc.), user changes are
// immediate -- each action is its own API call, not a batched save.

import { useEffect, useState } from "react";
import {
  ActionIcon,
  Alert,
  Badge,
  Button,
  Card,
  Group,
  Loader,
  Modal,
  PasswordInput,
  Select,
  Stack,
  Table,
  Text,
  TextInput,
  ThemeIcon,
  Tooltip,
} from "@mantine/core";
import { modals } from "@mantine/modals";
import { notifications } from "@mantine/notifications";
import {
  IconInfoCircle,
  IconKey,
  IconPlus,
  IconTrash,
  IconUserCog,
  IconUserOff,
  IconUsers,
} from "@tabler/icons-react";
import { api, ApiError, type User } from "../../../lib/api";
import { useAuth } from "../../../lib/auth-context";

const ROLE_OPTIONS = [
  { value: "admin", label: "Admin" },
  { value: "member", label: "Member" },
];

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function errorMessage(e: unknown): string {
  return e instanceof ApiError ? e.message : e instanceof Error ? e.message : String(e);
}

export function UsersManager() {
  const { token, email: selfEmail, isAdmin } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);

  // Add-user modal
  const [addOpen, setAddOpen] = useState(false);
  const [addEmail, setAddEmail] = useState("");
  const [addRole, setAddRole] = useState<string>("member");
  const [addPassword, setAddPassword] = useState("");
  const [adding, setAdding] = useState(false);

  // Reset-password modal
  const [resetUser, setResetUser] = useState<User | null>(null);
  const [resetPassword, setResetPassword] = useState("");
  const [resetting, setResetting] = useState(false);

  // Per-row busy state (role change / activate-deactivate / delete)
  const [busyId, setBusyId] = useState<string | null>(null);

  const load = () => {
    if (!token) return;
    setLoading(true);
    api
      .listUsers(token)
      .then((r) => setUsers(r.users))
      .catch((e) => notifications.show({ color: "red", message: errorMessage(e) }))
      .finally(() => setLoading(false));
  };

  useEffect(load, [token]);

  if (!isAdmin) {
    // Non-admins get no write surface at all; the backend would 403 anyway,
    // so don't even offer the controls (matches RuleEditor's convention).
    return (
      <Card withBorder radius="md" p="md">
        <Group mb="xs">
          <ThemeIcon variant="light" color="blue" size="sm">
            <IconUsers size={14} />
          </ThemeIcon>
          <Text fz="sm" fw={600}>Users</Text>
        </Group>
        <Alert color="yellow" icon={<IconInfoCircle size={16} />}>
          User management is admin-only.
        </Alert>
      </Card>
    );
  }

  function openAdd() {
    setAddEmail("");
    setAddRole("member");
    setAddPassword("");
    setAddOpen(true);
  }

  async function submitAdd() {
    if (!token) return;
    setAdding(true);
    try {
      await api.createUser(token, {
        email: addEmail.trim(),
        role: addRole,
        password: addPassword || undefined,
      });
      notifications.show({ color: "teal", message: `Added ${addEmail.trim()}` });
      setAddOpen(false);
      load();
    } catch (e) {
      notifications.show({ color: "red", message: errorMessage(e) });
    } finally {
      setAdding(false);
    }
  }

  async function changeRole(user: User, role: string) {
    if (!token || role === user.role) return;
    setBusyId(user.id);
    try {
      await api.updateUser(token, user.id, { role });
      setUsers((us) => us.map((u) => (u.id === user.id ? { ...u, role } : u)));
      notifications.show({ color: "teal", message: `${user.email} is now ${role}` });
    } catch (e) {
      notifications.show({ color: "red", message: errorMessage(e) });
    } finally {
      setBusyId(null);
    }
  }

  async function toggleActive(user: User) {
    if (!token) return;
    const nextActive = !user.is_active;
    setBusyId(user.id);
    try {
      await api.updateUser(token, user.id, { is_active: nextActive });
      setUsers((us) => us.map((u) => (u.id === user.id ? { ...u, is_active: nextActive } : u)));
      notifications.show({
        color: "teal",
        message: `${user.email} ${nextActive ? "activated" : "deactivated"}`,
      });
    } catch (e) {
      notifications.show({ color: "red", message: errorMessage(e) });
    } finally {
      setBusyId(null);
    }
  }

  function openReset(user: User) {
    setResetPassword("");
    setResetUser(user);
  }

  async function submitReset() {
    if (!token || !resetUser) return;
    setResetting(true);
    try {
      await api.updateUser(token, resetUser.id, { password: resetPassword });
      notifications.show({ color: "teal", message: `Password reset for ${resetUser.email}` });
      setResetUser(null);
    } catch (e) {
      notifications.show({ color: "red", message: errorMessage(e) });
    } finally {
      setResetting(false);
    }
  }

  function deleteUser(user: User) {
    modals.openConfirmModal({
      title: "Delete user",
      children: (
        <Text size="sm">
          Delete <b>{user.email}</b>? They will immediately lose access to this tenant. This
          cannot be undone.
        </Text>
      ),
      labels: { confirm: "Delete", cancel: "Cancel" },
      confirmProps: { color: "red" },
      onConfirm: async () => {
        if (!token) return;
        setBusyId(user.id);
        try {
          await api.deleteUser(token, user.id);
          setUsers((us) => us.filter((u) => u.id !== user.id));
          notifications.show({ color: "teal", message: `Deleted ${user.email}` });
        } catch (e) {
          notifications.show({ color: "red", message: errorMessage(e) });
        } finally {
          setBusyId(null);
        }
      },
    });
  }

  const addEmailError =
    addEmail && !EMAIL_RE.test(addEmail.trim()) ? "Enter a valid email address" : null;

  return (
    <Card withBorder radius="md" p="md">
      <Group justify="space-between" mb="xs">
        <Group gap="xs">
          <ThemeIcon variant="light" color="blue" size="sm">
            <IconUsers size={14} />
          </ThemeIcon>
          <Text fz="sm" fw={600}>Users</Text>
        </Group>
        <Button size="xs" variant="light" leftSection={<IconPlus size={14} />} onClick={openAdd}>
          Add user
        </Button>
      </Group>

      <Text fz="xs" c="dimmed" mb="sm">
        Colleagues with access to this tenant&apos;s console. Admins can manage users, tenant/S3
        settings, and destructive device commands; members can&apos;t.
      </Text>

      {loading ? (
        <Group justify="center" py="md">
          <Loader size="sm" />
        </Group>
      ) : users.length === 0 ? (
        <Alert variant="light" color="gray" icon={<IconInfoCircle size={16} />}>
          No users found.
        </Alert>
      ) : (
        <Table verticalSpacing="xs" withRowBorders={false}>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Email</Table.Th>
              <Table.Th>Role</Table.Th>
              <Table.Th>Status</Table.Th>
              <Table.Th>Sign-in</Table.Th>
              <Table.Th w={140} />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {users.map((u) => {
              const isSelf = u.email.toLowerCase() === (selfEmail ?? "").toLowerCase();
              const rowBusy = busyId === u.id;
              return (
                <Table.Tr key={u.id}>
                  <Table.Td>
                    <Group gap={6}>
                      <Text fz="sm">{u.email}</Text>
                      {isSelf && (
                        <Badge size="xs" variant="outline" color="gray">
                          you
                        </Badge>
                      )}
                    </Group>
                  </Table.Td>
                  <Table.Td>
                    <Select
                      size="xs"
                      w={110}
                      data={ROLE_OPTIONS}
                      value={u.role}
                      onChange={(v) => v && changeRole(u, v)}
                      disabled={rowBusy}
                      allowDeselect={false}
                      comboboxProps={{ withinPortal: true }}
                    />
                  </Table.Td>
                  <Table.Td>
                    <Badge
                      size="sm"
                      variant="light"
                      color={u.is_active ? "teal" : "gray"}
                    >
                      {u.is_active ? "Active" : "Inactive"}
                    </Badge>
                  </Table.Td>
                  <Table.Td>
                    <Text fz="xs" c="dimmed">
                      {u.external_id ? "External (SSO)" : u.has_password ? "Password" : "Not set"}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Group gap={4} justify="flex-end" wrap="nowrap">
                      {!u.external_id && (
                        <Tooltip label="Reset password" withArrow>
                          <ActionIcon
                            variant="subtle"
                            color="gray"
                            onClick={() => openReset(u)}
                            disabled={rowBusy}
                          >
                            <IconKey size={16} />
                          </ActionIcon>
                        </Tooltip>
                      )}
                      <Tooltip label={isSelf ? "Can't deactivate your own account" : u.is_active ? "Deactivate" : "Activate"} withArrow>
                        <ActionIcon
                          variant="subtle"
                          color={u.is_active ? "orange" : "teal"}
                          onClick={() => toggleActive(u)}
                          disabled={rowBusy || (isSelf && u.is_active)}
                        >
                          {u.is_active ? <IconUserOff size={16} /> : <IconUserCog size={16} />}
                        </ActionIcon>
                      </Tooltip>
                      <Tooltip label={isSelf ? "Can't delete your own account" : "Delete"} withArrow>
                        <ActionIcon
                          variant="subtle"
                          color="red"
                          onClick={() => deleteUser(u)}
                          disabled={rowBusy || isSelf}
                        >
                          <IconTrash size={16} />
                        </ActionIcon>
                      </Tooltip>
                    </Group>
                  </Table.Td>
                </Table.Tr>
              );
            })}
          </Table.Tbody>
        </Table>
      )}

      {/* Add user */}
      <Modal opened={addOpen} onClose={() => setAddOpen(false)} title="Add user" size="md">
        <Stack gap="md">
          <TextInput
            label="Email"
            placeholder="colleague@example.com"
            value={addEmail}
            onChange={(e) => setAddEmail(e.currentTarget.value)}
            error={addEmailError}
            withAsterisk
          />
          <Select
            label="Role"
            data={ROLE_OPTIONS}
            value={addRole}
            onChange={(v) => setAddRole(v ?? "member")}
            allowDeselect={false}
          />
          <PasswordInput
            label="Initial password"
            description="Required for local-auth tenants; leave blank if this tenant uses SSO."
            placeholder="Password"
            value={addPassword}
            onChange={(e) => setAddPassword(e.currentTarget.value)}
          />
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setAddOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={submitAdd}
              loading={adding}
              disabled={!addEmail.trim() || !!addEmailError}
            >
              Add user
            </Button>
          </Group>
        </Stack>
      </Modal>

      {/* Reset password */}
      <Modal opened={!!resetUser} onClose={() => setResetUser(null)} title="Reset password" size="md">
        {resetUser && (
          <Stack gap="md">
            <Text fz="sm" c="dimmed">
              Set a new password for <b>{resetUser.email}</b>. They&apos;ll need to use it on their
              next sign-in.
            </Text>
            <PasswordInput
              label="New password"
              placeholder="New password"
              value={resetPassword}
              onChange={(e) => setResetPassword(e.currentTarget.value)}
              withAsterisk
              data-autofocus
            />
            <Group justify="flex-end">
              <Button variant="default" onClick={() => setResetUser(null)}>
                Cancel
              </Button>
              <Button onClick={submitReset} loading={resetting} disabled={!resetPassword}>
                Reset password
              </Button>
            </Group>
          </Stack>
        )}
      </Modal>
    </Card>
  );
}
