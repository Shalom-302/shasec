from enum import Enum
from enum import IntEnum as SourceIntEnum
from typing import Type


class _EnumBase:
    @classmethod
    def get_member_keys(cls: Type[Enum]) -> list[str]:
        return [name for name in cls.__members__.keys()]

    @classmethod
    def get_member_values(cls: Type[Enum]) -> list:
        return [item.value for item in cls.__members__.values()]


class IntEnum(_EnumBase, SourceIntEnum):
    """Integer Enum"""

    pass


class StrEnum(_EnumBase, str, Enum):
    """String Enum"""

    pass



class LoginLogStatusType(IntEnum):
    """Login Log Status"""

    fail = 0
    success = 1



class StatusType(IntEnum):
    """Status Type"""

    disable = 0
    enable = 1


class MethodType(StrEnum):
    """Request method"""

    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    DELETE = 'DELETE'
    PATCH = 'PATCH'
    OPTIONS = 'OPTIONS'


class OperaLogCipherType(IntEnum):
    """Operation log encryption type"""

    aes = 0
    md5 = 1
    itsdangerous = 2
    plan = 3

class RoleDataScopeType(IntEnum):
    """Data range"""

    all = 1
    custom = 2


class User_job_status(Enum):
    OPEN_TO_WORK = "open_to_work" #Disponible pour un emploi ou des opportunités professionnelles.
    EMPLOYED = "employed" #Actuellement employé.
    NOT_LOOKING = "not_looking" #Pas à la recherche d'opportunités pour le moment.
    AVAILABLE_FOR_FREELANCE = "available_for_freelance" #Disponible pour des missions freelance ou des contrats à court terme.
    ON_LEAVE = "on_leave" #En congé ou indisponible pour une période définie.
    LOOKING_FOR_INTERNSHIP = "looking_for_internship" #Recherche activement un stage ou une opportunité d'apprentissage.
    OPEN_TO_COLLABORATION = "open_to_collaboration" #Ouvert à des collaborations ou des projets en partenariat.
    HIRED = "hired" #A trouvé un emploi ou est actuellement employé.

class Role(Enum):
    USER = "user"
    ADMIN = "admin"
    MENTOR = "mentor"
    COMPANY = "company"

class Appointment_status(Enum):
    WAITING_FOR_PAYMENT = "waiting_for_payment"
    PENDING = "pending"
    CANCELED = "canceled"
    DONE = "done"

class Payment_type(Enum):
    PAYIN = "payin"
    PAYOUT = "payout"
    
class Contract_type(Enum):
    CDI = "cdi"  # Contrat à Durée Indéterminée (CDI).
    CDD = "cdd"  # Contrat à Durée Déterminée (CDD).

class Collab_invitation_status_type(Enum):
    WAITING_FOR_RESPONSE = "waiting_for_response"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    CANCELED = "canceled"
    
class Collab_invitation_type(Enum):
    COLLABORATOR = "collaborator"
    RECRUTMENT = "recrutment"

class Program_follow_request_status(Enum):
    PENDING = "pending"
    WAITING_FOR_PAYMENT = "waiting_for_payment"
    PAID = "paid"
    CANCELED = "canceled"

    
class Week_task_status(Enum):
    IN_REVIEW = "in_review"
    COMPLETED = "completed"
    PENDING = "pending"
    REJECTED = "rejected"

class Mentor_request_status(Enum):
    PENDING = "Pending"
    APPROVED = "Approved"
    REJECTED = "Rejected"

class Transaction_status(Enum):
    PENDING = "pending"
    SUCCESSFULLY = "successfully"
    CANCELED = "canceled"
    
class Secure_token_type(Enum):
    RESET_PWD = "reset_pwd"
    VERIFY_ACCOUNT = "verif_account"
    UPDATE_EMAIL = "update_email"
    
class Waiting_queue_filter_type(Enum):
    COURSE = "course"
    PROGRAM = "program"

class Reason_type(Enum):
    COMPANY = "company"
    USER = "user"


# ---------------------------------------------------------------------------
# SHASEC — security-audit domain enums
# ---------------------------------------------------------------------------
class TargetType(StrEnum):
    """Kind of asset being audited."""

    website = "website"
    api = "api"
    graphql = "graphql"
    host = "host"


class ScanStatus(StrEnum):
    """Lifecycle of a scan. The Scan.status column is the single source of truth.

awaiting_approval (advanced/active audit, credits reserved) -> queued
    (approved by an admin, waiting for a worker slot) -> running -> completed | failed
    """

    pending = "pending"
    awaiting_approval = "awaiting_approval"
    # Domain audit: cartography done, waiting for the operator to pick which
    # discovered hosts are in scope for the active phases.
    awaiting_scope = "awaiting_scope"
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"


class ScanMode(StrEnum):
    """What a scan covers.

    - ``single`` : one URL, every stage in one pass (the historical behaviour).
    - ``audit``  : a whole domain, in the five-step hunt — 1 cartography
      (subdomains, live hosts, stack), then a human scope gate, then per selected
      host 2 passive+active scanning, 3 anonymous access, 4 controlled
      validation (proofs), and 5 the report, generated on demand only.
    """

    single = "single"
    audit = "audit"


class ExploitAggression(StrEnum):
    """How hard the exploit stage probes an AUTHORIZED target.

    - ``safe``       : curated, minimal bounded probes (the default).
    - ``aggressive`` : widen *coverage* — full bounded path/credential lists and
      a wider (still sequential, self-paced) ID range for BOLA.

    Aggression only ever widens bounded, non-destructive, in-scope probing. It
    NEVER enables destructive write verbs (that stays behind ``allow_destructive``)
    and NEVER raises request volume into flood/DoS territory — louder than this
    requires the shared rate-limiter (not yet built).
    """

    safe = "safe"
    aggressive = "aggressive"


class ScanProfile(StrEnum):
    """Depth/speed trade-off for a scan, mapped onto the methodology's staged
    "chaîne de chasse" (§3): recon fast, escalate to deep only where warranted.

    - ``fast``     : cheap recon/fingerprint plugins only (~seconds to ~2 min).
    - ``standard`` : fast + the main vuln scanners, minus the heavy long tail.
    - ``deep``     : everything, including nmap/testssl/ffuf/zap.

    An agent (Hermes) scans ``fast`` first, then requests ``deep`` on the assets
    that justify it — instead of firing every heavyweight tool on every target.
    """

    fast = "fast"
    standard = "standard"
    deep = "deep"


# A plugin runs when the scan's profile rank is >= the plugin's tier rank.
PROFILE_RANK: dict[str, int] = {
    ScanProfile.fast.value: 1,
    ScanProfile.standard.value: 2,
    ScanProfile.deep.value: 3,
}

# Overall wall-clock budget (seconds) for the scanner stage per profile. Plugins
# still running when the budget elapses are cancelled; findings already produced
# are kept. This is what actually bounds "the scan takes too long".
PROFILE_BUDGET: dict[str, int] = {
    ScanProfile.fast.value: 150,
    ScanProfile.standard.value: 480,
    ScanProfile.deep.value: 1500,
}


class FindingSeverity(StrEnum):
    """Normalized severity, scanner-agnostic."""

    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class FindingConfidence(StrEnum):
    """How sure we are a finding is real.

    Methodology (Kaanari "Chasse aux Sorcières" §14): every finding carries a
    confidence. An AI agent (Hermes) must declare it instead of asserting impact
    — low until corroborated, high only when a proof row backs it.
    """

    low = "low"
    medium = "medium"
    high = "high"


class FindingStatus(StrEnum):
    """Lifecycle of a finding (methodology §14).

    A scanner observation enters as ``suspected``; it only becomes ``confirmed``
    when a proof (an Exploit row) demonstrates it. This separation — observed vs.
    potential — is what keeps an autonomous agent's work honest.
    """

    suspected = "suspected"
    confirmed = "confirmed"
    false_positive = "false_positive"
    stopped = "stopped"
    fixed = "fixed"
    retest_required = "retest_required"


class ReportFormat(StrEnum):
    """Supported report output formats."""

    pdf = "pdf"
    html = "html"
    markdown = "markdown"
    json = "json"


# Numeric weight per severity — used by the aggregator to compute the criticality
# of a correlated finding (max wins) and by the AI scoring as a prior.
SEVERITY_WEIGHT: dict[str, int] = {
    FindingSeverity.critical.value: 5,
    FindingSeverity.high.value: 4,
    FindingSeverity.medium.value: 3,
    FindingSeverity.low.value: 2,
    FindingSeverity.info.value: 1,
}

class CreditKind(StrEnum):
    """What a credit grant buys.

    - ``free_scan`` : one-shot discovery scans given at signup (counted in scans,
      not credits; results only, no downloadable report).
    - ``credit``    : Kortex credits (bought, redeemed from a voucher, monthly
      subscription allowance or granted by an admin). Scans billed with credits
      unlock detailed reports.
    """

    free_scan = "free_scan"
    credit = "credit"


class CreditSource(StrEnum):
    """Where a credit grant comes from (audit trail / support)."""

    signup = "signup"
    voucher = "voucher"
    purchase = "purchase"
    subscription = "subscription"
    admin = "admin"


class CreditTxReason(StrEnum):
    """Why a ledger line moved the balance."""

    grant = "grant"
    scan_debit = "scan_debit"
    scan_refund = "scan_refund"


class ScanBilling(StrEnum):
    """How a scan was paid for. Drives entitlements (e.g. reports)."""

    free = "free"
    credits = "credits"
    admin = "admin"
