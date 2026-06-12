import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from backend.common.enums import FindingSeverity


@dataclass
class ScanContext:
    """Everything a plugin needs to run against one target."""

    scan_id: int
    target_url: str
    target_type: str
    options: dict = field(default_factory=dict)


@dataclass
class RawFinding:
    """A plugin's native finding, before normalization/correlation.

    The orchestrator tags it with the plugin name and computes the correlation
    fingerprint, so plugins only describe *what* they found.
    """

    title: str
    severity: str = FindingSeverity.info.value
    description: str | None = None
    evidence: str | None = None
    recommendation: str | None = None
    # Optional explicit dedup seed; falls back to the title when absent.
    fingerprint_seed: str | None = None


class ScannerPlugin(ABC):
    """The single contract every scanner obeys.

    External scanners (nuclei, nmap, zap...) wrap a subprocess/API; internal ones
    (this http checker, jwt, graphql...) are pure Python. Both return the same
    ``RawFinding`` shape, so the rest of the pipeline never knows the difference.
    """

    #: unique short name; also stored on each Finding.plugin
    name: str = 'base'
    #: target types this plugin handles; empty tuple = all types
    handles: tuple[str, ...] = ()
    #: hard timeout for a single run, in seconds
    timeout: int = 120

    def supports(self, target_type: str) -> bool:
        return not self.handles or target_type in self.handles

    @abstractmethod
    async def run(self, ctx: ScanContext) -> list[RawFinding]:
        """Execute against ``ctx.target_url`` and return raw findings."""
        raise NotImplementedError


async def run_command(args: list[str], timeout: int, stdin: bytes | None = None) -> tuple[int, str, str]:
    """Run an external scanner as a subprocess with a hard timeout.

    Returns ``(returncode, stdout, stderr)``. Kills the process on timeout so a
    hung scanner can never block the pipeline forever.
    """
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdin=asyncio.subprocess.PIPE if stdin is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(input=stdin), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise TimeoutError(f'command timed out after {timeout}s: {args[0]}')
    return proc.returncode or 0, out.decode(errors='replace'), err.decode(errors='replace')
