import typer
import httpx
import yaml
import json
import os
from pathlib import Path
from typing import Optional, List
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax
from rich.panel import Panel
from rich import print as rprint
from datetime import datetime
import asyncio
from functools import wraps

app = typer.Typer(help="Micromanage CLI")
console = Console()

# Configuration
CONFIG_FILE = Path.home() / ".mmmdm" / "config.json"
DEFAULT_API_URL = os.getenv("MICROMANAGE_MDM_API_URL", "http://localhost:8001")

class Config:
    def __init__(self):
        self.api_url = DEFAULT_API_URL
        self.token = None
        self.tenant_id = None
        self.user_email = None
        self.load()
    
    def load(self):
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, 'r') as f:
                data = json.load(f)
                self.api_url = data.get('api_url', self.api_url)
                self.token = data.get('token')
                self.tenant_id = data.get('tenant_id')
                self.user_email = data.get('user_email')
    
    def save(self):
        # The config holds a bearer token, so keep it readable only by its owner.
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(CONFIG_FILE.parent, 0o700)
        except OSError:
            pass
        # Create with restrictive perms before writing any secret material.
        fd = os.open(CONFIG_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            json.dump({
                'api_url': self.api_url,
                'token': self.token,
                'tenant_id': self.tenant_id,
                'user_email': self.user_email
            }, f)
        try:
            os.chmod(CONFIG_FILE, 0o600)
        except OSError:
            pass
    
    def clear(self):
        self.token = None
        self.tenant_id = None
        self.user_email = None
        self.save()

config = Config()

def async_command(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        return asyncio.run(func(*args, **kwargs))
    return wrapper

async def make_request(method: str, endpoint: str, **kwargs):
    """Make authenticated API request"""
    headers = kwargs.pop('headers', {})
    if config.token:
        headers['Authorization'] = f'Bearer {config.token}'
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.request(
            method,
            f"{config.api_url}/api/v1{endpoint}",
            headers=headers,
            **kwargs
        )

        # A 401 from /auth/login just means the credentials were wrong; let
        # the login command report that itself. Anywhere else, 401 means the
        # session is gone (expired, revoked, tenant deactivated).
        if response.status_code == 401 and endpoint != '/auth/login':
            console.print("[red]Authentication failed. Please login again.[/red]")
            raise typer.Exit(1)

        return response

# Auth commands
@app.command()
@async_command
async def login(
    tenant_id: str = typer.Option(..., prompt=True),
    user_email: str = typer.Option(..., prompt=True),
    password: str = typer.Option(..., prompt=True, hide_input=True)
):
    """Login to MDM system"""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task("Authenticating...", total=None)

        response = await make_request(
            'POST',
            '/auth/login',
            json={'tenant_id': tenant_id, 'user_email': user_email, 'password': password}
        )
    
    if response.status_code == 200:
        data = response.json()
        config.token = data['access_token']
        config.tenant_id = tenant_id
        config.user_email = user_email
        config.save()
        
        console.print(f"[green]✓ Logged in successfully as {user_email}[/green]")
        console.print(f"[dim]Tenant: {tenant_id}[/dim]")
    else:
        console.print(f"[red]Login failed: {response.json().get('detail', 'Unknown error')}[/red]")
        raise typer.Exit(1)

@app.command()
def logout():
    """Logout from MDM system"""
    config.clear()
    console.print("[green]✓ Logged out successfully[/green]")

@app.command()
def whoami():
    """Show current user information"""
    if not config.token:
        console.print("[red]Not logged in[/red]")
        raise typer.Exit(1)
    
    console.print(f"[cyan]User:[/cyan] {config.user_email}")
    console.print(f"[cyan]Tenant:[/cyan] {config.tenant_id}")
    console.print(f"[cyan]API URL:[/cyan] {config.api_url}")

# Tenant commands
@app.command()
@async_command
async def tenant_info():
    """Show tenant information"""
    response = await make_request('GET', '/tenant')
    
    if response.status_code == 200:
        tenant = response.json()
        
        panel = Panel(
            f"[bold]{tenant['name']}[/bold]\n"
            f"ID: {tenant['id']}\n"
            f"DEP Enabled: {'Yes' if tenant['dep_enabled'] else 'No'}\n"
            f"Active: {'Yes' if tenant['is_active'] else 'No'}\n"
            f"Created: {tenant['created_at'][:10]}\n\n"
            f"[cyan]Allowed Users:[/cyan]\n" +
            '\n'.join(f"  • {user}" for user in tenant['allowed_users']),
            title="Tenant Information",
            border_style="blue"
        )
        console.print(panel)
    else:
        console.print(f"[red]Failed to get tenant info: {response.status_code}[/red]")

@app.command()
@async_command
async def tenant_update(
    name: Optional[str] = None,
    add_user: Optional[List[str]] = typer.Option(None, "--add-user", "-a"),
    remove_user: Optional[List[str]] = typer.Option(None, "--remove-user", "-r"),
    dep_enabled: Optional[bool] = None
):
    """Update tenant configuration"""
    # Get current tenant info
    response = await make_request('GET', '/tenant')
    if response.status_code != 200:
        console.print("[red]Failed to get current tenant info[/red]")
        raise typer.Exit(1)
    
    tenant = response.json()
    update_data = {}
    
    if name:
        update_data['name'] = name
    
    if add_user or remove_user:
        users = tenant['allowed_users']
        if add_user:
            users.extend(add_user)
        if remove_user:
            users = [u for u in users if u not in remove_user]
        update_data['allowed_users'] = list(set(users))
    
    if dep_enabled is not None:
        update_data['dep_enabled'] = dep_enabled
    
    if not update_data:
        console.print("[yellow]No updates specified[/yellow]")
        return
    
    response = await make_request('PUT', '/tenant', json=update_data)
    
    if response.status_code == 200:
        console.print("[green]✓ Tenant updated successfully[/green]")
    else:
        console.print(f"[red]Failed to update tenant: {response.json()}[/red]")

# YAML configuration commands
yaml_app = typer.Typer(help="Manage YAML configurations")
app.add_typer(yaml_app, name="yaml")

# Flows commands
flows_app = typer.Typer(help="Manage ATC flows")
app.add_typer(flows_app, name="flows")


@flows_app.command("migrate")
@async_command
async def flows_migrate(
    dry_run: bool = typer.Option(False, "--dry-run", help="Validate without writing"),
):
    """Migrate flows.yaml to the multi-flow v2 format.

    Normalization happens automatically on every read; this command forces the
    on-disk document to be rewritten to the v2 schema.
    """
    response = await make_request("GET", "/config/flows")
    if response.status_code != 200:
        console.print(f"[red]Failed to get flows configuration: {response.text}[/red]")
        raise typer.Exit(1)

    version = response.headers.get("X-Config-Version")
    doc = response.json()
    headers = {"If-Match": version} if version else None
    params = {"dry_run": "true"} if dry_run else {}

    put_resp = await make_request("PUT", "/config/flows", json=doc, headers=headers, params=params)
    if put_resp.status_code == 200:
        result = put_resp.json()
        if dry_run:
            console.print("[green]✓ Dry run valid (no changes committed)[/green]")
        else:
            console.print("[green]✓ flows.yaml migrated to v2 schema successfully[/green]")
        if result.get("warnings"):
            console.print("[yellow]Warnings:[/yellow]")
            for w in result["warnings"]:
                console.print(f"  ⚠️  {w}")
        if result.get("gate_findings"):
            console.print("[yellow]Gate findings:[/yellow]")
            for f in result["gate_findings"]:
                console.print(f"  ℹ️  [{f.get('code')}] {f.get('message')}")
    else:
        console.print(f"[red]Migration failed: {put_resp.text}[/red]")
        raise typer.Exit(1)

@yaml_app.command("get")
@async_command
async def yaml_get(
    config_type: str = typer.Argument(
        ..., help="Config type: groups, apps, profiles, tags, flows, dispatcher, "
                   "declarations, or config"
    ),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file")
):
    """Get YAML configuration"""
    response = await make_request('GET', f'/config/{config_type}')
    
    if response.status_code == 200:
        config_data = response.json()
        yaml_content = yaml.dump(config_data, default_flow_style=False)
        
        if output:
            output.write_text(yaml_content)
            console.print(f"[green]✓ Configuration saved to {output}[/green]")
        else:
            syntax = Syntax(yaml_content, "yaml", theme="monokai", line_numbers=True)
            console.print(syntax)
    else:
        console.print(f"[red]Failed to get configuration: {response.json()}[/red]")

@yaml_app.command("update")
@async_command
async def yaml_update(
    config_type: str = typer.Argument(
        ..., help="Config type: groups, apps, profiles, tags, declarations, "
                   "flows, or dispatcher (the last two need the admin role)"
    ),
    file: Path = typer.Argument(..., help="YAML file to upload")
):
    """Update YAML configuration"""
    if not file.exists():
        console.print(f"[red]File not found: {file}[/red]")
        raise typer.Exit(1)
    
    try:
        with open(file, 'r') as f:
            config_data = yaml.safe_load(f)
    except Exception as e:
        console.print(f"[red]Failed to parse YAML: {e}[/red]")
        raise typer.Exit(1)
    
    response = await make_request('PUT', f'/config/{config_type}', json=config_data)
    
    if response.status_code == 200:
        result = response.json()
        console.print(f"[green]✓ {result['message']}[/green]")
        
        if result.get('warnings'):
            console.print("[yellow]Warnings:[/yellow]")
            for warning in result['warnings']:
                console.print(f"  ⚠️  {warning}")
    else:
        error_data = response.json()
        console.print(f"[red]Failed to update configuration[/red]")
        
        if 'detail' in error_data and isinstance(error_data['detail'], dict):
            if error_data['detail'].get('errors'):
                console.print("[red]Errors:[/red]")
                for error in error_data['detail']['errors']:
                    console.print(f"  [red]{error}[/red]")
            if error_data['detail'].get('warnings'):
                console.print("[yellow]Warnings:[/yellow]")
                for warning in error_data['detail']['warnings']:
                    console.print(f"  ⚠️  {warning}")

@yaml_app.command("validate")
@async_command
async def yaml_validate():
    """Validate all YAML configurations"""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task("Validating configurations...", total=None)
        response = await make_request('POST', '/config/validate')
    
    if response.status_code == 200:
        result = response.json()
        
        if result['valid']:
            console.print("[green]✓ All configurations are valid![/green]")
        else:
            console.print("[red]✗ Configuration validation failed[/red]")
        
        if result.get('errors'):
            console.print("\n[red]Errors:[/red]")
            for error in result['errors']:
                console.print(f"  [red]{error}[/red]")
        
        if result.get('warnings'):
            console.print("\n[yellow]Warnings:[/yellow]")
            for warning in result['warnings']:
                console.print(f"  ⚠️  {warning}")
    else:
        console.print(f"[red]Validation failed: {response.json()}[/red]")

# Device commands
device_app = typer.Typer(help="Manage devices")
app.add_typer(device_app, name="device")

@device_app.command("list")
@async_command
async def device_list(
    group: Optional[str] = None,
    model: Optional[str] = None,
    limit: int = 50
):
    """List devices"""
    params = {'limit': limit}
    if group:
        params['group'] = group
    if model:
        params['model'] = model
    
    response = await make_request('GET', '/devices', params=params)
    
    if response.status_code == 200:
        data = response.json()
        
        if not data['devices']:
            console.print("[yellow]No devices found[/yellow]")
            return
        
        table = Table(title=f"Devices (Total: {data['total']})")
        table.add_column("Serial Number", style="cyan")
        table.add_column("Model", style="magenta")
        table.add_column("OS Version", style="green")
        table.add_column("Hostname", style="yellow")
        table.add_column("Groups", style="blue")
        table.add_column("Last Seen", style="dim")
        
        for device in data['devices']:
            groups = ', '.join(device['groups'][:2])
            if len(device['groups']) > 2:
                groups += f" (+{len(device['groups']) - 2})"
            
            last_seen = datetime.fromisoformat(device['last_seen'].replace('Z', '+00:00'))
            last_seen_str = last_seen.strftime("%Y-%m-%d %H:%M")
            
            table.add_row(
                device['serial_number'],
                device['device_model'],
                device['os_version'],
                device.get('hostname', 'N/A'),
                groups,
                last_seen_str
            )
        
        console.print(table)
    else:
        console.print(f"[red]Failed to list devices: {response.json()}[/red]")

@device_app.command("info")
@async_command
async def device_info(device_id: str):
    """Show detailed device information"""
    response = await make_request('GET', f'/devices/{device_id}')
    
    if response.status_code == 200:
        data = response.json()
        device = data['device']
        
        # Device info panel
        device_panel = Panel(
            f"[bold]{device['hostname'] or 'Unknown'}[/bold]\n"
            f"Serial: {device['serial_number']}\n"
            f"UDID: {device['udid']}\n"
            f"Model: {device['device_model']}\n"
            f"OS Version: {device['os_version']}\n"
            f"Groups: {', '.join(device['groups'])}\n"
            f"Enrolled: {device['enrollment_date'][:10]}\n"
            f"Last Seen: {device['last_seen'][:16]}",
            title="Device Information",
            border_style="blue"
        )
        console.print(device_panel)
        
        # Apps table
        if data['installed_apps']:
            console.print("\n[bold]Installed Apps:[/bold]")
            app_table = Table()
            app_table.add_column("App ID", style="cyan")
            app_table.add_column("Version", style="green")
            app_table.add_column("Status", style="yellow")
            app_table.add_column("Install Date", style="dim")
            
            for app in data['installed_apps']:
                app_table.add_row(
                    app['app_id'],
                    app['version'],
                    app['status'],
                    app['install_date'][:10] if app['install_date'] else 'N/A'
                )
            console.print(app_table)
        
        # Profiles table
        if data['installed_profiles']:
            console.print("\n[bold]Installed Profiles:[/bold]")
            profile_table = Table()
            profile_table.add_column("Profile ID", style="cyan")
            profile_table.add_column("Status", style="yellow")
            profile_table.add_column("Install Date", style="dim")
            
            for profile in data['installed_profiles']:
                profile_table.add_row(
                    profile['profile_id'],
                    profile['status'],
                    profile['install_date'][:10] if profile['install_date'] else 'N/A'
                )
            console.print(profile_table)
        
        # Recent tasks
        if data['recent_tasks']:
            console.print("\n[bold]Recent Tasks:[/bold]")
            for task in data['recent_tasks'][:5]:
                status_emoji = {
                    'pending': '⏳',
                    'running': '🔄',
                    'completed': '✅',
                    'failed': '❌',
                    'cancelled': '🚫'
                }.get(task['status'], '❓')
                
                console.print(f"{status_emoji} {task['description']} - {task['status']}")
                if task['error']:
                    console.print(f"   [red]Error: {task['error']}[/red]")
    else:
        console.print(f"[red]Device not found[/red]")

@device_app.command("commands")
@async_command
async def device_commands():
    """List every command the server can send, with its parameters"""
    response = await make_request('GET', '/commands/catalog')

    if response.status_code != 200:
        console.print(f"[red]Failed to load command catalog: {response.json()}[/red]")
        raise typer.Exit(1)

    commands = response.json()['commands']

    table = Table(title="Device Commands")
    table.add_column("Command", style="cyan")
    table.add_column("Category", style="magenta")
    table.add_column("Description", style="white")
    table.add_column("Params", style="yellow")
    table.add_column("Admin only", style="red", justify="center")

    for cmd in sorted(commands, key=lambda c: (c['category'], c['type'])):
        params = ', '.join(p['name'] for p in cmd['params']) or '-'
        table.add_row(
            cmd['type'],
            cmd['category'],
            cmd['description'],
            params,
            '✓' if cmd['destructive'] else ''
        )

    console.print(table)
    console.print("\n[dim]Send one with: device command <device_id> <command> "
                   "[--param name=value ...][/dim]")


@device_app.command("command")
@async_command
async def device_command(
    device_id: str,
    command: str = typer.Argument(..., help="Command type; run 'device commands' for the full list"),
    param: Optional[List[str]] = typer.Option(
        None, "--param", "-p",
        help="Command parameter as name=value (repeatable)"
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y",
        help="Skip the confirmation prompt for destructive commands"
    ),
):
    """Send a command to a device"""
    catalog_response = await make_request('GET', '/commands/catalog')
    if catalog_response.status_code != 200:
        console.print(f"[red]Failed to load command catalog: {catalog_response.json()}[/red]")
        raise typer.Exit(1)

    entry = next(
        (c for c in catalog_response.json()['commands'] if c['type'] == command), None
    )
    if entry is None:
        console.print(
            f"[red]Unknown command '{command}'. Run 'device commands' to see what's available.[/red]"
        )
        raise typer.Exit(1)
    if not entry['allowed']:
        console.print(f"[red]'{command}' requires the admin role.[/red]")
        raise typer.Exit(1)

    parameters = {}
    for item in param or []:
        if '=' not in item:
            console.print(f"[red]--param must be name=value, got: {item}[/red]")
            raise typer.Exit(1)
        name, _, value = item.partition('=')
        parameters[name] = value

    missing = [p['label'] for p in entry['params']
               if p.get('required') is True and not parameters.get(p['name'])]
    if missing:
        console.print(f"[red]Missing required parameter(s): {', '.join(missing)}[/red]")
        raise typer.Exit(1)

    # The server also gates destructive commands on role (admin-only) and would
    # reject this anyway, but asking here avoids sending a command the operator
    # didn't mean to fire.
    if entry['destructive'] and not yes:
        if not typer.confirm(f"'{command}' is destructive: {entry['description']} Continue?"):
            raise typer.Abort()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task(f"Sending {command} command...", total=None)

        response = await make_request(
            'POST',
            f'/devices/{device_id}/command',
            json={'command_type': command, 'parameters': parameters}
        )

    if response.status_code == 200:
        result = response.json()
        console.print(f"[green]✓ {result['message']}[/green]")

        if 'task_id' in result:
            console.print(f"[dim]Task ID: {result['task_id']}[/dim]")
    else:
        console.print(f"[red]Command failed: {response.json()}[/red]")

# Task commands
task_app = typer.Typer(help="Manage tasks")
app.add_typer(task_app, name="task")

@task_app.command("list")
@async_command
async def task_list(
    status: Optional[str] = None,
    device_id: Optional[str] = None,
    limit: int = 20
):
    """List tasks"""
    params = {'limit': limit}
    if status:
        params['status'] = status
    if device_id:
        params['device_id'] = device_id
    
    response = await make_request('GET', '/tasks', params=params)
    
    if response.status_code == 200:
        data = response.json()
        
        if not data['tasks']:
            console.print("[yellow]No tasks found[/yellow]")
            return
        
        table = Table(title=f"Tasks (Total: {data['total']})")
        table.add_column("Status", style="cyan", width=8)
        table.add_column("Type", style="magenta")
        table.add_column("Description", style="white")
        table.add_column("Device", style="yellow")
        table.add_column("Progress", style="green", width=10)
        table.add_column("Created", style="dim")
        
        for task in data['tasks']:
            status_emoji = {
                'pending': '⏳',
                'running': '🔄',
                'completed': '✅',
                'failed': '❌',
                'cancelled': '🚫'
            }.get(task['status'], '❓')
            
            device_name = 'N/A'
            if task.get('device_id'):
                device_name = (task.get('device') or {}).get('serial_number', 'Device')
            
            progress_str = f"{task['progress']}%" if task['status'] == 'running' else "-"
            
            created = datetime.fromisoformat(task['created_at'].replace('Z', '+00:00'))
            created_str = created.strftime("%m-%d %H:%M")
            
            table.add_row(
                f"{status_emoji} {task['status']}",
                task['type'],
                task['description'][:40] + ('...' if len(task['description']) > 40 else ''),
                device_name,
                progress_str,
                created_str
            )
        
        console.print(table)
    else:
        console.print(f"[red]Failed to list tasks: {response.json()}[/red]")

@task_app.command("info")
@async_command
async def task_info(task_id: str):
    """Show task details"""
    response = await make_request('GET', f'/tasks/{task_id}')
    
    if response.status_code == 200:
        task = response.json()
        
        status_color = {
            'pending': 'yellow',
            'running': 'blue',
            'completed': 'green',
            'failed': 'red',
            'cancelled': 'magenta'
        }.get(task['status'], 'white')
        
        panel_content = f"[bold]Type:[/bold] {task['type']}\n"
        panel_content += f"[bold]Status:[/bold] [{status_color}]{task['status']}[/{status_color}]\n"
        panel_content += f"[bold]Progress:[/bold] {task['progress']}%\n"
        panel_content += f"[bold]Created:[/bold] {task['created_at']}\n"
        
        if task['started_at']:
            panel_content += f"[bold]Started:[/bold] {task['started_at']}\n"
        if task['completed_at']:
            panel_content += f"[bold]Completed:[/bold] {task['completed_at']}\n"
        
        if task['error']:
            panel_content += f"\n[bold red]Error:[/bold red]\n{task['error']}"
        
        if task['details']:
            panel_content += f"\n\n[bold]Details:[/bold]\n"
            for key, value in task['details'].items():
                panel_content += f"  {key}: {value}\n"
        
        panel = Panel(
            panel_content,
            title=f"Task: {task['description']}",
            border_style=status_color
        )
        console.print(panel)
    else:
        console.print(f"[red]Task not found[/red]")

@task_app.command("cancel")
@async_command
async def task_cancel(task_id: str):
    """Cancel a running task"""
    response = await make_request('POST', f'/tasks/{task_id}/cancel')
    
    if response.status_code == 200:
        result = response.json()
        console.print(f"[green]✓ {result['message']}[/green]")
    else:
        console.print(f"[red]Failed to cancel task: {response.json()}[/red]")

# Stats commands
stats_app = typer.Typer(help="View statistics")
app.add_typer(stats_app, name="stats")

@stats_app.command("overview")
@async_command
async def stats_overview():
    """Show overview statistics"""
    response = await make_request('GET', '/stats/overview')
    
    if response.status_code == 200:
        stats = response.json()
        
        # Devices panel
        devices_panel = Panel(
            f"[bold]Total:[/bold] {stats['devices']['total']}\n"
            f"[bold]Active (7d):[/bold] {stats['devices']['active_7d']}",
            title="Devices",
            border_style="blue"
        )
        
        # Tasks panel
        task_stats = stats['tasks']
        tasks_content = f"[bold]Total:[/bold] {task_stats['total']}\n"
        if task_stats.get('by_status'):
            tasks_content += "\n[bold]By Status:[/bold]\n"
            for status, count in task_stats['by_status'].items():
                tasks_content += f"  {status}: {count}\n"
        tasks_content += f"\n[bold]Running:[/bold] {task_stats.get('running', 0)}"
        
        tasks_panel = Panel(
            tasks_content,
            title="Tasks",
            border_style="green"
        )
        
        # Deployments panel
        deployments_panel = Panel(
            f"[bold]Apps:[/bold] {stats['deployments']['apps']}\n"
            f"[bold]Profiles:[/bold] {stats['deployments']['profiles']}",
            title="Deployments",
            border_style="yellow"
        )
        
        # Display panels
        console.print(devices_panel)
        console.print(tasks_panel)
        console.print(deployments_panel)
    else:
        console.print(f"[red]Failed to get statistics: {response.json()}[/red]")

@stats_app.command("devices")
@async_command
async def stats_devices(
    by: str = typer.Argument("model", help="Group by: model or os")
):
    """Show device statistics"""
    if by not in ['model', 'os']:
        console.print("[red]Invalid grouping. Use 'model' or 'os'[/red]")
        raise typer.Exit(1)
    
    endpoint = f'/stats/devices/by-{by}'
    response = await make_request('GET', endpoint)
    
    if response.status_code == 200:
        data = response.json()
        
        if not data:
            console.print("[yellow]No data available[/yellow]")
            return
        
        table = Table(title=f"Devices by {by.upper()}")
        table.add_column(by.capitalize(), style="cyan")
        table.add_column("Count", style="green", justify="right")
        table.add_column("Percentage", style="yellow", justify="right")
        
        total = sum(item['count'] for item in data)
        data.sort(key=lambda x: x['count'], reverse=True)

        # /stats/devices/by-model rows are keyed "device_model"; by-os rows are
        # keyed "os_version" (they group by different Device columns).
        row_key = {'model': 'device_model', 'os': 'os_version'}[by]
        for item in data:
            key = item[row_key] or 'Unknown'
            count = item['count']
            percentage = (count / total * 100) if total > 0 else 0
            
            table.add_row(
                key,
                str(count),
                f"{percentage:.1f}%"
            )
        
        console.print(table)
        console.print(f"\n[dim]Total devices: {total}[/dim]")
    else:
        console.print(f"[red]Failed to get statistics: {response.json()}[/red]")

# Main CLI
@app.callback()
def main(
    api_url: Optional[str] = typer.Option(None, "--api-url", envvar="MICROMANAGE_MDM_API_URL"),
    version: bool = typer.Option(False, "--version", "-v")
):
    """Micromanage Command Line Interface"""
    if version:
        console.print("Micromanage CLI v1.0.0")
        raise typer.Exit()
    
    if api_url:
        config.api_url = api_url
        config.save()

if __name__ == "__main__":
    app()