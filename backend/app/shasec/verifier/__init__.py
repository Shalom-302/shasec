import importlib
import logging
import pkgutil

from backend.app.shasec.verifier.base import ExploitModule

logger = logging.getLogger(__name__)

_REGISTRY: dict[str, ExploitModule] = {}
_discovered = False


def register(module: ExploitModule) -> None:
    _REGISTRY[module.name] = module


def _discover() -> None:
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
            logger.error("Failed to load shasec exploit module '%s': %s", mod.name, exc)


def get_modules() -> list[ExploitModule]:
    _discover()
    return list(_REGISTRY.values())


def get_modules_for(target_type: str) -> list[ExploitModule]:
    return [m for m in get_modules() if m.supports(target_type)]
