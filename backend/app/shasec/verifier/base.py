from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from backend.common.enums import FindingSeverity


@dataclass
class ExploitContext:
    """Input to an exploit module. Only ever built for an authorized target with
    explicit active-exploitation consent."""

    scan_id: int
    target_url: str
    target_type: str
    options: dict = field(default_factory=dict)
    # Optional valid token the operator provides, to test authenticated flows
    # (e.g. JWT tampering, BFLA from a low-priv account).
    auth_token: str | None = None


@dataclass
class ExploitResult:
    """A proof of exploitability, with the request/response that demonstrates it."""

    category: str
    title: str
    severity: str = FindingSeverity.info.value
    confirmed: bool = False
    impact: str | None = None
    request: str | None = None
    response: str | None = None


class ExploitModule(ABC):
    """Contract for an active-exploitation module.

    Modules must be SAFE: read-only / non-destructive by default, bounded
    (no bulk exfiltration), in-scope (only the target host), and they must record
    the exact request/response on every ExploitResult — that record IS the audit
    trail.
    """

    name: str = 'base'
    category: str = 'generic'
    handles: tuple[str, ...] = ()
    timeout: int = 60

    def supports(self, target_type: str) -> bool:
        return not self.handles or target_type in self.handles

    @abstractmethod
    async def run(self, ctx: ExploitContext) -> list[ExploitResult]:
        raise NotImplementedError
