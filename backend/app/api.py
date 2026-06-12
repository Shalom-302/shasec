import importlib
import logging
import pkgutil

from fastapi import APIRouter

from backend.app import Handlers
from backend.core.conf import settings

logger = logging.getLogger(__name__)

# Single unified API router: admin (auth/users/roles/RBAC/logs) and shasec
# (targets/scans/findings) are served under one app so there is one Swagger and
# one base path (`/api/v1`). To log in and test product routes in the same docs.
api_router = APIRouter(prefix=f"{settings.FASTAPI_API_V1_PATH}")


for handler in Handlers.iterator():
    if getattr(handler, 'router', None):
        if handler.__name__.split('.')[-4] in ('admin', 'shasec'):
            api_router.include_router(handler.router)


def _load_plugins() -> None:
    """Auto-discover plugins added with `shaapi add <name>`.

    Each plugin lives in ``backend/plugins/<name>/`` and exposes a ``router`` in
    its ``router`` module. Nothing is imported unless the plugin exists — the
    opposite of loading every plugin at startup. A fresh project has no
    ``backend/plugins`` package, so this is a no-op there.
    """
    try:
        import backend.plugins as plugins_pkg
    except ModuleNotFoundError:
        return
    for mod_info in pkgutil.iter_modules(plugins_pkg.__path__):
        if mod_info.name.startswith('_'):
            continue
        module_name = f'backend.plugins.{mod_info.name}.router'
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to load plugin '%s': %s", mod_info.name, exc)
            continue
        router = getattr(module, 'router', None)
        if router is not None:
            api_router.include_router(router)
            logger.info("Loaded plugin '%s'", mod_info.name)


_load_plugins()
