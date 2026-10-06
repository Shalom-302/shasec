import importlib
import logging
import pkgutil

from backend.app.shasec.plugins.base import ScannerPlugin

logger = logging.getLogger(__name__)

# name -> plugin instance
_REGISTRY: dict[str, ScannerPlugin] = {}
_discovered = False


def register(plugin: ScannerPlugin) -> None:
    """Called by each plugin module at import time to self-register."""
    _REGISTRY[plugin.name] = plugin


def _discover() -> None:
    """Import every plugin module in this package once so they self-register.

    Drop a new ``backend/app/shasec/plugins/<name>.py`` that calls ``register()``
    and it is picked up automatically — no central list to edit.
    """
    global _discovered
    if _discovered:
        return
    _discovered = True
    for mod in pkgutil.iter_modules(__path__):
        if mod.name == 'base' or mod.name.startswith('_'):
            continue
        try:
            importlib.import_module(f'{__name__}.{mod.name}')
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to load shasec plugin module '%s': %s", mod.name, exc)


def get_plugins() -> list[ScannerPlugin]:
    _discover()
    return list(_REGISTRY.values())


def get_plugins_for(target_type: str, profile: str = 'standard') -> list[ScannerPlugin]:
    """Plugins handling ``target_type`` whose tier is within the scan ``profile``.

    A plugin runs when PROFILE_RANK[profile] >= PROFILE_RANK[plugin.tier], so
    ``fast`` runs only fast-tier plugins and ``deep`` runs everything.
    """
    from backend.common.enums import PROFILE_RANK

    ceiling = PROFILE_RANK.get(profile, PROFILE_RANK['standard'])
    return [
        p for p in get_plugins()
        if p.supports(target_type) and PROFILE_RANK.get(getattr(p, 'tier', 'standard'), 2) <= ceiling
    ]
