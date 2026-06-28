"""Privileged tenant/user management CLI.

Run inside the controller environment, e.g.::

    python -m controller.tenant_cli user add default admin@example.com --role admin
    python -m controller.tenant_cli user set-password default admin@example.com
    python -m controller.tenant_cli tenant create acme --name "Acme Inc"

This is the supported way to provision local-auth users (passwords are bcrypt
hashed; they are never stored or logged in clear text).
"""

import asyncio
from functools import wraps

import typer
from rich.console import Console
from rich.table import Table

from controller.auth import ROLES, ROLE_MEMBER
from controller.auth.passwords import hash_password
from controller.models.database import init_db, close_db
from controller.models.tenant import Tenant, User

app = typer.Typer(help="Micromanage tenant/user administration")
tenant_app = typer.Typer(help="Manage tenants")
user_app = typer.Typer(help="Manage users")
app.add_typer(tenant_app, name="tenant")
app.add_typer(user_app, name="user")
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
    await User.create(
        tenant=tenant,
        email=email,
        role=role,
        external_id=external_id,
        password_hash=hash_password(password) if password else None,
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
    user.password_hash = hash_password(password)
    await user.save()
    console.print(f"[green]✓ Updated password for {email}[/green]")


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


if __name__ == "__main__":
    app()
