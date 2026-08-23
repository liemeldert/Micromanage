import hashlib
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import boto3
from botocore.config import Config
from controller.models.tenant import AppDeployment, Device, Tenant
from controller.services import readiness
from controller.services.group_manager import GroupManager
from controller.services.mdm_connector import MDMConnector
from controller.services.scoping import (
    device_in_rollout,
    device_platform_category,
    evaluate_scope,
)

logger = logging.getLogger(__name__)

# S3 settings that decide which object store we talk to and whose credentials sign the request. Resolved as an
# all-or-nothing block, never field by field, or a tenant could name a bucket and get the operator's keys pointed
# at it. prefix is excluded.
TENANT_S3_KEYS = (
    "bucket", "access_key_id", "secret_access_key", "session_token",
    "endpoint_url", "region", "use_ssl", "path_style",
)

# What a tenant-supplied block cannot work without; region and transport fall back to the constants below instead.
REQUIRED_TENANT_S3_KEYS = ("bucket", "access_key_id", "secret_access_key")

DEFAULT_S3_REGION = "us-east-1"
DEFAULT_S3_USE_SSL = True
DEFAULT_S3_PATH_STYLE = False


class S3ConfigError(RuntimeError):
    """A tenant's S3 settings cannot be resolved from a single source.

    Raised only when object storage is used, not when an AppManager is built.
    """


def _is_set(value: Any) -> bool:
    """Whether an author actually supplied this setting.

    use_ssl: false counts, which is why this is not a truthiness test. An empty string does not, since that is what a
    cleared form field and a blank YAML value both serialize to.
    """
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    return True


def _as_bool(value: Any, default: bool) -> bool:
    """Coerce a config toggle that may have arrived as a string.

    Needed because a str-valued path renders false as "False", which is truthy in Python.
    """
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, str):
        text = value.strip().lower()
        if text in ("true", "yes", "on", "1"):
            return True
        if text in ("false", "no", "off", "0", ""):
            return False
    return bool(value)


@dataclass(frozen=True)
class S3Settings:
    """Everything needed to reach one tenant's object store, from one source.

    source ("tenant" or "environment") records which, so nothing here is ever a blend of the two.
    """
    bucket: Optional[str]
    access_key_id: Optional[str]
    secret_access_key: Optional[str]
    session_token: Optional[str]
    region: str
    endpoint_url: Optional[str]
    use_ssl: bool
    path_style: bool
    prefix: str
    source: str


def no_bucket_error(tenant_id: Any) -> S3ConfigError:
    """The error for a tenant that resolves to no bucket at all.

    Only reachable from the ambient environment, since a tenant that describes its own object store already has to name
    a bucket in it. Shared with the readiness predicate rather than written out twice, so both answer in one sentence.
    """
    return S3ConfigError(
        f"No S3 bucket is configured for tenant '{tenant_id}'. This tenant has "
        "no S3 configuration of its own, so Micromanage uses the server "
        "environment, where AWS_S3_BUCKET is empty. Set AWS_S3_BUCKET for the "
        "deployment, or give this tenant its own bucket and credentials in its "
        "S3 configuration."
    )


def _incomplete_config_error(tenant_id: Any, declared: List[str],
                             missing: List[str]) -> S3ConfigError:
    return S3ConfigError(
        f"Tenant '{tenant_id}' has an incomplete S3 configuration: it sets "
        f"{', '.join(declared)} but not {', '.join(missing)}. Micromanage will "
        "not use the AWS credentials in the server environment to reach a bucket "
        "a tenant chose, because those credentials belong to the deployment and "
        "not to this tenant. Either add the missing settings to this "
        "tenant's S3 configuration (Settings, S3 section, or the s3: block in "
        "its config.yaml), or clear that configuration entirely so the tenant "
        "uses the server's own bucket and credentials together."
    )


def resolve_s3_settings(tenant: Tenant) -> S3Settings:
    """Resolve one tenant's S3 settings from exactly one trust domain.

    No tenant S3 config: falls back to the ambient AWS environment. Any TENANT_S3_KEYS set: must supply its
    own full config, environment is never read.
    """
    s3_config = tenant.s3_config or {}
    # A hand-edited config or direct DB write could leave this as a list or string; every line below is a .get(),
    # so guard here rather than let an AttributeError escape and abort this tenant's whole sync cycle.
    if not isinstance(s3_config, dict):
        raise S3ConfigError(
            f"Tenant '{tenant.id}' has an S3 configuration that is not a set of "
            f"settings (it is a {type(s3_config).__name__}). Replace it with a "
            "mapping of S3 settings, or clear it entirely so the tenant uses "
            "the server's own bucket and credentials."
        )
    prefix = str(s3_config.get("prefix") or "")

    declared = [k for k in TENANT_S3_KEYS if _is_set(s3_config.get(k))]
    if not declared:
        return S3Settings(
            bucket=os.getenv("AWS_S3_BUCKET"),
            access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            session_token=os.getenv("AWS_SESSION_TOKEN"),
            region=os.getenv("AWS_DEFAULT_REGION") or DEFAULT_S3_REGION,
            endpoint_url=os.getenv("AWS_S3_ENDPOINT_URL"),
            # No env vars for these two: they are tenant settings only, and reading them from the deployment would put a
            # transport decision in one domain and the endpoint it applies to in the other.
            use_ssl=DEFAULT_S3_USE_SSL,
            path_style=DEFAULT_S3_PATH_STYLE,
            prefix=prefix,
            source="environment",
        )

    missing = [k for k in REQUIRED_TENANT_S3_KEYS if not _is_set(s3_config.get(k))]
    if missing:
        raise _incomplete_config_error(tenant.id, declared, missing)

    return S3Settings(
        bucket=str(s3_config["bucket"]).strip(),
        access_key_id=str(s3_config["access_key_id"]).strip(),
        secret_access_key=str(s3_config["secret_access_key"]).strip(),
        session_token=(str(s3_config["session_token"]).strip()
                       if _is_set(s3_config.get("session_token")) else None),
        region=(str(s3_config["region"]).strip()
                if _is_set(s3_config.get("region")) else DEFAULT_S3_REGION),
        endpoint_url=(str(s3_config["endpoint_url"]).strip()
                      if _is_set(s3_config.get("endpoint_url")) else None),
        use_ssl=_as_bool(s3_config.get("use_ssl"), DEFAULT_S3_USE_SSL),
        path_style=_as_bool(s3_config.get("path_style"), DEFAULT_S3_PATH_STYLE),
        prefix=prefix,
        source="tenant",
    )


class AppManager:
    def __init__(self, tenant: Tenant):
        self.tenant = tenant
        self._s3_client = None
        self.group_manager = GroupManager(tenant.id)

    @property
    def s3_client(self):
        """boto3 client for this tenant's object store, built on first use.

        Not built in __init__: an incomplete S3 config would then abort this tenant's entire reconcile cycle,
        including profile and DDM reconciliation, which never touch S3.
        """
        if self._s3_client is None:
            self._s3_client = self._init_s3_client()
        return self._s3_client

    def _init_s3_client(self):
        """S3 client for this tenant. See resolve_s3_settings for the rules."""
        settings = resolve_s3_settings(self.tenant)

        config = Config(
            region_name=settings.region,
            s3={
                'addressing_style': 'path' if settings.path_style else 'virtual'
            }
        )

        client_kwargs = {
            'service_name': 's3',
            'aws_access_key_id': settings.access_key_id,
            'aws_secret_access_key': settings.secret_access_key,
            'config': config,
            'use_ssl': settings.use_ssl,
        }

        # Only alongside a full key pair: botocore rejects a token with a half-set pair, and with no pair at all
        # the client should fall through to botocore's own credential chain instead.
        if settings.session_token and settings.access_key_id and settings.secret_access_key:
            client_kwargs['aws_session_token'] = settings.session_token

        if settings.endpoint_url:  # non-AWS S3 (MinIO and friends)
            client_kwargs['endpoint_url'] = settings.endpoint_url

        return boto3.client(**client_kwargs)

    async def evaluate_device_apps(
        self, device: Device, apps_config: List[Dict[str, Any]],
        groups_config: List[Dict[str, Any]],
        device_groups: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Which apps should be installed on a device.

        Also persists the freshly-computed group membership. device_groups lets a caller that already evaluated
        it skip recomputing.
        """
        if device_groups is None:
            device_groups = self.group_manager.evaluate_device_groups(device, groups_config)
        changed = device_groups != (device.groups or [])
        device.groups = device_groups
        if changed:
            # Save groups alone: a full save would overwrite fields another writer touched (poller's last_polled_at).
            # Only on an actual change, since this runs per device per cycle.
            await device.save(update_fields=["groups"])

        apps_to_install = []
        now = datetime.now(timezone.utc)

        for app in apps_config:
            app_version = self._get_applicable_version(device, app, device_groups, now)
            if app_version:
                entry = {
                    'app_id': app['id'],
                    'name': app['name'],
                    'bundle_id': app['bundle_id'],
                    'version': app_version['version'],
                    's3_key': app_version['s3_key'],
                    'sha256': app_version.get('sha256'),
                    'install_options': app_version.get('install_options', {})
                }
                # Only when the author said something. Absent means managed on a Mac, which is what the deploy path
                # defaults to, so a missing key changes nothing and an authored False is never mistaken for one.
                if 'install_as_managed' in app:
                    entry['install_as_managed'] = app['install_as_managed']
                apps_to_install.append(entry)

        return apps_to_install

    def _get_applicable_version(
        self, device: Device, app: Dict[str, Any], device_groups: List[str],
        now: Optional[datetime] = None,
    ) -> Optional[Dict[str, Any]]:
        """Newest version the device is both scoped and waved into.

        Versions are stored oldest-first; walks in reverse so a held rollout falls through to the next-older
        version rather than leaving the device with nothing.
        """
        for version in reversed(app.get('versions', [])):
            if not evaluate_scope(device, device_groups, version):
                continue
            rollout = version.get('rollout')
            if rollout and not device_in_rollout(
                device, rollout, f"app:{app.get('id')}:{version.get('version')}", now
            ):
                continue  # held, so fall through to the next-older version
            return version

        return None

    def _get_s3_bucket(self) -> str:
        """The bucket this tenant's packages live in.

        Comes from the same source as the credentials that will address it, so this can't be the tenant's bucket signed
        with the deployment's keys.
        """
        settings = resolve_s3_settings(self.tenant)
        if not settings.bucket:
            raise no_bucket_error(self.tenant.id)
        return settings.bucket

    def package_store_error(self) -> Optional[str]:
        """Why this tenant cannot serve app packages at all, or None if it can.

        Delegates to readiness.check('app_install') so the readiness endpoint and the reconciler agree.
        """
        status = readiness.check(readiness.APP_INSTALL, tenant=self.tenant)
        return None if status.ready else status.reason

    def scoped_app_ids(self, device: Device, apps_config: List[Dict[str, Any]],
                       device_groups: List[str]) -> set:
        """Every app id this device is scoped into, rollout waves included.

        Broader than evaluate_device_apps (what to install now): a caller checking whether the device left an
        app's scope must not confuse a held rollout with a departed scope.
        """
        scoped = set()
        for app in apps_config:
            if not isinstance(app, dict) or app.get('id') is None:
                continue
            for version in app.get('versions', []):
                if evaluate_scope(device, device_groups, version):
                    scoped.add(app['id'])
                    break
        return scoped

    def _get_s3_prefix(self) -> str:
        s3_config = self.tenant.s3_config or {}
        return str(s3_config.get('prefix') or '')

    def _build_s3_key(self, app_s3_key: str) -> str:
        """The object key for an apps.yaml key: the tenant prefix in front of it."""
        prefix = self._get_s3_prefix()
        if prefix and not prefix.endswith('/'):
            prefix += '/'
        return f"{prefix}{app_s3_key}" if prefix else app_s3_key

    def _strip_s3_prefix(self, full_key: str) -> str:
        """The apps.yaml form of a key: the object key without the tenant prefix."""
        prefix = self._get_s3_prefix()
        if prefix and not prefix.endswith('/'):
            prefix += '/'
        if prefix and full_key.startswith(prefix):
            return full_key[len(prefix):]
        return full_key

    # The sha256 the manifest needs is not something S3 keeps (an ETag is an MD5, and only for single-part uploads), so
    # it lives in object metadata under this key. The upload endpoint writes it; list_packages reads it;
    # checksum_package fills it in for objects that arrived some other way.
    SHA256_METADATA_KEY = 'sha256'
    LIST_LIMIT = 1000

    def list_packages(self) -> List[Dict[str, Any]]:
        """Objects under this tenant's prefix.

        Synchronous boto3; call through asyncio.to_thread. Only the first LIST_LIMIT objects get a HEAD for their
        sha256 metadata; past that the checksum comes back unknown rather than the listing taking a minute.
        """
        bucket = self._get_s3_bucket()
        prefix = self._get_s3_prefix()
        if prefix and not prefix.endswith('/'):
            prefix += '/'
        paginator = self.s3_client.get_paginator('list_objects_v2')
        kwargs = {'Bucket': bucket}
        if prefix:
            kwargs['Prefix'] = prefix
        out: List[Dict[str, Any]] = []
        for page in paginator.paginate(**kwargs):
            for obj in page.get('Contents', []) or []:
                key = obj['Key']
                if key.endswith('/'):
                    continue  # a folder marker, not a package
                entry = {
                    'key': self._strip_s3_prefix(key),
                    'size': obj.get('Size'),
                    'last_modified': (obj['LastModified'].isoformat()
                                      if obj.get('LastModified') else None),
                    'sha256': None,
                }
                if len(out) < self.LIST_LIMIT:
                    try:
                        head = self.s3_client.head_object(Bucket=bucket, Key=key)
                        entry['sha256'] = (head.get('Metadata') or {}).get(
                            self.SHA256_METADATA_KEY) or None
                    except Exception:
                        pass
                out.append(entry)
        out.sort(key=lambda e: e.get('last_modified') or '', reverse=True)
        return out

    def storage_usage_bytes(self) -> int:
        """Bytes under this tenant's prefix right now. Synchronous; use to_thread.

        A listing, not a cached counter, so packages that arrived outside the upload endpoint count too. Cheap at the
        sizes an MDM tenant holds (a few hundred objects at most).
        """
        bucket = self._get_s3_bucket()
        prefix = self._get_s3_prefix()
        if prefix and not prefix.endswith('/'):
            prefix += '/'
        paginator = self.s3_client.get_paginator('list_objects_v2')
        kwargs = {'Bucket': bucket}
        if prefix:
            kwargs['Prefix'] = prefix
        total = 0
        for page in paginator.paginate(**kwargs):
            for obj in page.get('Contents', []) or []:
                total += int(obj.get('Size') or 0)
        return total

    def storage_quota_bytes(self) -> Optional[int]:
        """The ceiling that applies to this tenant, or None for unlimited.

        The tenant's own value wins when set; otherwise the deployment default from MDM_DEFAULT_STORAGE_QUOTA_BYTES,
        read per call. Zero or less on either means no ceiling.
        """
        own = getattr(self.tenant, 'storage_quota_bytes', None)
        if own is not None:
            return int(own) if int(own) > 0 else None
        raw = (os.getenv('MDM_DEFAULT_STORAGE_QUOTA_BYTES') or '').strip()
        try:
            default = int(raw) if raw else 0
        except ValueError:
            logger.warning("MDM_DEFAULT_STORAGE_QUOTA_BYTES is not a number: %r; ignoring", raw)
            default = 0
        return default if default > 0 else None

    def checksum_package(self, app_s3_key: str) -> str:
        """sha256 of an object already in the bucket, recorded on it for next time.

        Synchronous; call through asyncio.to_thread. Rewrites the object's metadata via a server-side S3 copy
        onto itself; a failure to write that back is logged but the digest is still returned.
        """
        bucket = self._get_s3_bucket()
        full_key = self._build_s3_key(app_s3_key)
        obj = self.s3_client.get_object(Bucket=bucket, Key=full_key)
        digest = hashlib.sha256()
        body = obj['Body']
        for chunk in iter(lambda: body.read(1024 * 1024), b''):
            digest.update(chunk)
        sha = digest.hexdigest()
        try:
            metadata = dict(obj.get('Metadata') or {})
            metadata[self.SHA256_METADATA_KEY] = sha
            self.s3_client.copy_object(
                Bucket=bucket, Key=full_key,
                CopySource={'Bucket': bucket, 'Key': full_key},
                Metadata=metadata, MetadataDirective='REPLACE',
                ContentType=obj.get('ContentType') or 'application/octet-stream',
            )
        except Exception:
            logger.warning("could not record sha256 on s3://%s/%s", bucket, full_key,
                           exc_info=True)
        return sha

    async def ensure_deployment(self, device: Device, app_info: Dict[str, Any],
                                task_id: Optional[str] = None,
                                source: Optional[str] = None) -> AppDeployment:
        """Get-or-create the (device, app) deployment row and link it to the attempt about to run.

        Split out of deploy_app so a caller that already created the Task can stamp the link early, before the
        Task can be lost to a restart while queued. Idempotent: deploy_app calls this again once it actually runs.
        """
        deployment, created = await AppDeployment.get_or_create(
            tenant=self.tenant,
            device=device,
            app_id=app_info['app_id'],
            defaults={
                'app_version': app_info['version'],
                'status': 'pending',
                'last_task_id': task_id,
                'install_source': source,
            }
        )

        dirty: List[str] = []
        if not created and deployment.app_version != app_info['version']:
            deployment.app_version = app_info['version']
            deployment.status = 'pending'
            dirty += ['app_version', 'status']
        if task_id and str(deployment.last_task_id) != str(task_id):
            deployment.last_task_id = task_id
            dirty.append('last_task_id')
        if source and deployment.install_source != source:
            deployment.install_source = source
            dirty.append('install_source')
        if dirty:
            await deployment.save(update_fields=dirty)

        return deployment

    async def deploy_app(self, device: Device, app_info: Dict[str, Any],
                         mdm_connector: 'MDMConnector', task_id: Optional[str] = None,
                         source: Optional[str] = None) -> AppDeployment:
        """Deploy an app to a device.

        source names whoever asked for an app the device is not scoped into, and reaches the deployment row through
        ensure_deployment. The handler reads it off the task's details, so every path that goes through a task carries
        it without knowing it exists.
        """
        from controller.models.tenant import Task

        # Row and link (see ensure_deployment) as early as this call can make them, before the MDM round trip below. A
        # no-op when a caller already made them earlier still.
        deployment = await self.ensure_deployment(device, app_info, task_id,
                                                  source=source)

        if task_id:
            task = await Task.get(id=task_id)
            task.details['app_id'] = app_info['app_id']
            task.details['version'] = app_info['version']
            await task.save()

        try:
            # The manifest itself is built and served by GET /api/manifests/{id} (api/main.py), which presigns the
            # download at the moment the device asks for it. Nothing is built here: a URL signed now would start ageing
            # before the command has even been pushed.
            manifest_url = f"{readiness.public_api_url()}/api/manifests/{deployment.id}"

            # Apple requires the ManifestURL to begin with https:, or the device fails with an error an admin can't
            # act on. Last check before the URL is actually sent; also catches an unset PUBLIC_API_URL.
            # https://raw.githubusercontent.com/apple/device-management/release/mdm/commands/application.install.yaml
            if not manifest_url.startswith("https://"):
                raise ValueError(
                    f"ManifestURL '{manifest_url}' is not https (check PUBLIC_API_URL); Apple requires https, so the "
                    "device would refuse this install"
                )

            # InstallAsManaged is macOS-only and is what makes ManagementFlags 1 mean anything. Managed by default on a
            # Mac and off only on an explicit False, so a missing or malformed key keeps the default. See
            # MDMConnector.install_app for the packages a managed install refuses.
            is_mac = device_platform_category(device.device_model) == "Mac"
            as_managed = is_mac and app_info.get('install_as_managed', True) is not False

            result = await mdm_connector.install_app(
                device.udid,
                manifest_url,
                # 1 removes the app when the MDM profile is removed, which is what the checkout handler assumes an
                # unenroll does. 4 would prevent backup, 5 both.
                management_flags=1,
                install_as_managed=as_managed,
            )

            deployment.status = 'installing'
            # One reading of the connector's answer for both deployment paths: a failed push leaves the command stored,
            # so the row stays installing and carries the reason it may sit there a while, and an attempt that pushed
            # cleanly replaces whatever the last one had to say.
            from controller.services.profile_manager import push_failure_note

            deployment.last_error = push_failure_note(result)
            await deployment.save()

            if task_id:
                task = await Task.get(id=task_id)
                task.status = 'running'
                task.details['command_uuid'] = result.get('command_uuid')
                await task.save()

            logger.info(f"App deployment initiated for {device.serial_number}: {result}")

        except Exception as e:
            deployment.status = 'failed'
            deployment.last_error = str(e)
            await deployment.save()

            if task_id:
                task = await Task.get(id=task_id)
                task.status = 'failed'
                task.error = str(e)
                # Terminal outside update_progress, so stamp what retention keys on.
                task.completed_at = datetime.now(timezone.utc)
                await task.save()

            logger.error(f"Failed to deploy app to {device.serial_number}: {e}")
            raise

        return deployment

    async def get_installed_apps(self, device: Device, mdm_connector: 'MDMConnector') -> Dict[str, Any]:
        """Ask the device for its InstalledApplicationList, answering empty when the command cannot be sent."""
        try:
            result = await mdm_connector.get_installed_apps(device.udid)
            return result
        except Exception as e:
            logger.error(f"Failed to get installed apps for {device.serial_number}: {e}")
            return {}

    async def remove_app(self, device: Device, app_id: str, bundle_id: str,
                         mdm_connector: 'MDMConnector', task_id: Optional[str] = None) -> bool:
        """Remove an app from a device"""
        from controller.models.tenant import Task

        try:
            result = await mdm_connector.remove_app(device.udid, bundle_id)

            deployment = await AppDeployment.get_or_none(
                device=device,
                app_id=app_id
            )
            if deployment:
                await deployment.delete()

            if task_id:
                # Wait for the device. The webhook completes the task.
                task = await Task.get(id=task_id)
                task.status = 'running'
                task.details['command_uuid'] = result.get('command_uuid')
                await task.save()

            return True

        except Exception as e:
            if task_id:
                task = await Task.get(id=task_id)
                task.status = 'failed'
                task.error = str(e)
                # Terminal outside update_progress, so stamp what retention keys on.
                task.completed_at = datetime.now(timezone.utc)
                await task.save()

            logger.error(f"Failed to remove app from {device.serial_number}: {e}")
            return False
