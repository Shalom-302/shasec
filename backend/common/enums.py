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
    """Lifecycle of a scan. The Scan.status column is the single source of truth."""

    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class FindingSeverity(StrEnum):
    """Normalized severity, scanner-agnostic."""

    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


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