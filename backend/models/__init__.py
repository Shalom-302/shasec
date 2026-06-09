import importlib
import pkgutil

from backend.common.model import Base

# Canonical models kept as explicit imports so `from backend.models import User`
# resolves for IDEs and type checkers.
from backend.models.casbin_rule import CasbinRule
from backend.models.role import Role
from backend.models.user import User
from backend.models.opera_log import OperaLog
from backend.models.login_log import LoginLog

# Auto-import every other module dropped in this package so Alembic
# autogenerate sees its tables without editing this file: just create
# `backend/models/<name>.py` with a `Base` subclass and run `shaapi db generate`.
# (Plugin models are discovered separately by alembic/env.py.)
for _module in pkgutil.iter_modules(__path__):
    if not _module.name.startswith("_"):
        importlib.import_module(f"{__name__}.{_module.name}")
del importlib, pkgutil