"""Privileged tenant/user management CLI (local-auth provisioning)."""

import asyncio
from datetime import datetime, timezone
from functools import wraps

import typer
from controller.auth import ROLE_MEMBER, ROLES
from controller.auth.passwords import hash_password, password_policy_error
from controller.models.database import close_db, init_db
from controller.models.tenant import Tenant, User
from controller.services import mfa
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Micromanage tenant/user administration")
tenant_app = typer.Typer(help="Manage tenants")
user_app = typer.Typer(help="Manage users")
schema_app = typer.Typer(help="Database schema state")
app.add_typer(tenant_app, name="tenant")
app.add_typer(user_app, name="user")
app.add_typer(schema_app, name="schema")
console = Console()


def with_db(func):
    """Wrap an async command so it runs inside an initialized DB connection."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        async def runner():
            await init_db()
            try:
                return await func(*args, **kwargs)
            finally:
                await close_db()

        return asyncio.run(runner())

    return wrapper


AUTH_PROVIDERS = ("local", "clerk", "oidc")


@tenant_app.command("create")
@with_db
async def tenant_create(
    tenant_id: str,
    name: str = typer.Option(None, help="Display name (defaults to the id)"),
    provider: str = typer.Option("local", help="Auth provider: local | clerk | oidc"),
):
    if provider not in AUTH_PROVIDERS:
        console.print(f"[red]provider must be one of {list(AUTH_PROVIDERS)}[/red]")
        raise typer.Exit(1)
    if await Tenant.get_or_none(id=tenant_id):
        console.print(f"[yellow]Tenant '{tenant_id}' already exists[/yellow]")
        raise typer.Exit(1)
    await Tenant.create(
        id=tenant_id, name=name or tenant_id, auth_config={"provider": provider}
    )
    console.print(f"[green]✓ Created tenant '{tenant_id}' (provider: {provider})[/green]")


@tenant_app.command("list")
@with_db
async def tenant_list():
    tenants = await Tenant.all()
    table = Table("ID", "Name", "Provider", "Active")
    for t in tenants:
        table.add_row(t.id, t.name, t.auth_provider, "yes" if t.is_active else "no")
    console.print(table)


@tenant_app.command("set-quota")
@with_db
async def tenant_set_quota(
    tenant_id: str,
    quota: str = typer.Argument(..., help='Bytes, with an optional unit (500MB, 2GB), or "unlimited"'),
):
    """Cap what a tenant may keep in its object store. Operator-only: a tenant's admins can read the value but not
    change it. "unlimited" clears the tenant's own value, so MDM_DEFAULT_STORAGE_QUOTA_BYTES applies again if set.
    """
    tenant = await _get_tenant(tenant_id)
    text = quota.strip().lower()
    if text in ("unlimited", "none", "off"):
        tenant.storage_quota_bytes = None
    else:
        units = {"b": 1, "kb": 1024, "mb": 1024 ** 2, "gb": 1024 ** 3, "tb": 1024 ** 4}
        number, unit = text, "b"
        for suffix in sorted(units, key=len, reverse=True):
            if text.endswith(suffix) and text != suffix:
                number, unit = text[: -len(suffix)].strip(), suffix
                break
        try:
            value = int(float(number) * units[unit])
        except ValueError:
            console.print(f"[red]could not read a size from {quota!r}[/red]")
            raise typer.Exit(1)
        if value < 0:
            console.print("[red]quota must not be negative[/red]")
            raise typer.Exit(1)
        tenant.storage_quota_bytes = value  # 0 means no ceiling
    await tenant.save(update_fields=["storage_quota_bytes", "updated_at"])
    shown = ("unlimited" if tenant.storage_quota_bytes in (None, 0)
             else f"{tenant.storage_quota_bytes} bytes")
    console.print(f"[green]✓ Storage quota for {tenant_id}: {shown}[/green]")


async def _get_tenant(tenant_id: str) -> Tenant:
    tenant = await Tenant.get_or_none(id=tenant_id)
    if not tenant:
        console.print(f"[red]No such tenant: {tenant_id}[/red]")
        raise typer.Exit(1)
    return tenant


@user_app.command("add")
@with_db
async def user_add(
    tenant_id: str,
    email: str,
    role: str = typer.Option(ROLE_MEMBER, help=f"One of: {', '.join(sorted(ROLES))}"),
    external_id: str = typer.Option(None, help="Provider subject id (for clerk/oidc)"),
    password: str = typer.Option(
        None,
        prompt="Password (leave blank for external-auth users)",
        confirmation_prompt=True,
        hide_input=True,
        help="Password for local auth (prompted if omitted)",
    ),
):
    if role not in ROLES:
        console.print(f"[red]role must be one of {sorted(ROLES)}[/red]")
        raise typer.Exit(1)
    tenant = await _get_tenant(tenant_id)
    if await User.get_or_none(tenant=tenant, email=email):
        console.print(f"[red]User {email} already exists for tenant {tenant_id}[/red]")
        raise typer.Exit(1)
    if password:
        problem = password_policy_error(password)
        if problem:
            console.print(f"[red]{problem}[/red]")
            raise typer.Exit(1)
    await User.create(
        tenant=tenant,
        email=email,
        role=role,
        external_id=external_id,
        password_hash=hash_password(password) if password else None,
        # When the current password was set, same as the API's create_user.
        password_changed_at=datetime.now(timezone.utc) if password else None,
    )
    console.print(f"[green]✓ Added {role} user {email} to tenant {tenant_id}[/green]")


@user_app.command("set-password")
@with_db
async def user_set_password(
    tenant_id: str,
    email: str,
    password: str = typer.Option(
        ..., prompt=True, confirmation_prompt=True, hide_input=True
    ),
):
    tenant = await _get_tenant(tenant_id)
    user = await User.get_or_none(tenant=tenant, email=email)
    if not user:
        console.print(f"[red]No such user: {email}[/red]")
        raise typer.Exit(1)
    problem = password_policy_error(password)
    if problem:
        console.print(f"[red]{problem}[/red]")
        raise typer.Exit(1)
    user.password_hash = hash_password(password)
    # Invalidates every session this user already has (auth.dependencies).
    user.password_changed_at = datetime.now(timezone.utc)
    await user.save()
    console.print(f"[green]✓ Updated password for {email}, and signed out their "
                  f"existing sessions[/green]")


@user_app.command("list")
@with_db
async def user_list(tenant_id: str):
    tenant = await _get_tenant(tenant_id)
    users = await User.filter(tenant=tenant).all()
    table = Table("Email", "Role", "Active", "Local password", "External id")
    for u in users:
        table.add_row(
            u.email, u.role, "yes" if u.is_active else "no",
            "yes" if u.password_hash else "no", u.external_id or "-",
        )
    console.print(table)


@user_app.command("remove")
@with_db
async def user_remove(tenant_id: str, email: str):
    tenant = await _get_tenant(tenant_id)
    user = await User.get_or_none(tenant=tenant, email=email)
    if not user:
        console.print(f"[red]No such user: {email}[/red]")
        raise typer.Exit(1)
    await user.delete()
    console.print(f"[green]✓ Removed {email} from tenant {tenant_id}[/green]")


@user_app.command("mfa-reset")
@with_db
async def user_mfa_reset(tenant_id: str, email: str):
    tenant = await _get_tenant(tenant_id)
    user = await User.get_or_none(tenant=tenant, email=email)
    if not user:
        console.print(f"[red]No such user: {email}[/red]")
        raise typer.Exit(1)
    if not await mfa.is_enabled(user):
        console.print(f"[red]User {email} does not have MFA enabled[/red]")
        raise typer.Exit(1)
    await mfa.disable(user)
    console.print(f"[green]✓ Disabled MFA for {email}, and signed out their "
                  f"existing sessions[/green]")


@schema_app.command("status")
def schema_status_cmd():
    """Report whether the database is at the schema this build expects, and since when."""
    from controller.models.database import init_db_no_schema, schema_status
    from controller.version import __version__

    async def runner():
        await init_db_no_schema()
        try:
            return await schema_status()
        finally:
            await close_db()

    status = asyncio.run(runner())
    console.print(f"controller version: {__version__}")
    console.print(f"expected fingerprint: {status['expected_fingerprint']}")
    console.print(f"recorded fingerprint: {status['recorded_fingerprint'] or '(none)'}")
    if status["recorded_at"]:
        console.print(f"recorded at: {status['recorded_at']} by controller "
                      f"{status['recorded_by_version']}")
    if status["current"]:
        console.print("[green]✓ database is at this build's schema[/green]")
    else:
        console.print("[yellow]database is not at this build's schema; starting any "
                      "controller process, or running schema apply, brings it there[/yellow]")
        raise typer.Exit(1)


@schema_app.command("apply")
def schema_apply_cmd():
    """Create missing tables and apply the aux DDL, exactly as a process start does."""
    from controller.models.database import init_db

    async def runner():
        await init_db()
        await close_db()

    asyncio.run(runner())
    console.print("[green]✓ schema applied[/green]")


if __name__ == "__main__":
    app()
