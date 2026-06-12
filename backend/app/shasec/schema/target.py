import ipaddress
from datetime import datetime
from urllib.parse import urlparse

from pydantic import ConfigDict, Field, model_validator

from backend.common.enums import TargetType
from backend.common.schema import SchemaBase

# Target types that designate a web endpoint and therefore require an http(s) URL.
# `host` is exempt: it may be a bare hostname or IP for network-level scanning.
_URL_TYPES = {TargetType.website.value, TargetType.api.value, TargetType.graphql.value}


def _is_local_host(host: str) -> bool:
    """True if a host is unreachable from a deployed (cloud) scanner.

    Local / private / loopback / link-local targets must be audited by the local
    shasec CLI agent, not by the deployed backend.
    """
    if not host:
        return True
    h = host.lower().strip()
    if h == 'localhost' or h.endswith('.local') or h.endswith('.internal'):
        return True
    try:
        ip = ipaddress.ip_address(h)
        return ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved
    except ValueError:
        # Not an IP literal. A bare hostname with no dot (e.g. "myserver") is an
        # internal name, so treat it as local too.
        return '.' not in h


class TargetSchemaBase(SchemaBase):
    name: str
    url: str
    type: TargetType = Field(default=TargetType.website)


class _ValidatedTargetParam(TargetSchemaBase):
    """Input base that enforces the deployed-scanner target rules.

    Only inbound params inherit this; read schemas keep the plain base so stored
    rows are never re-validated on output.
    """

    @model_validator(mode='after')
    def _validate_url(self):
        # `use_enum_values=True` means `self.type` is already the string value.
        type_value = self.type
        raw = (self.url or '').strip()
        parsed = urlparse(raw)

        if type_value in _URL_TYPES:
            if parsed.scheme not in ('http', 'https'):
                raise ValueError('url must start with http:// or https://')
            if not parsed.hostname:
                raise ValueError('url is missing a host')
            host = parsed.hostname
        else:  # host: accept a bare hostname / IP, or a scheme-prefixed URL
            host = parsed.hostname or raw

        if _is_local_host(host):
            raise ValueError(
                'Local or private targets are not reachable from the deployed scanner. '
                'Use the shasec CLI agent to audit local targets.'
            )

        self.url = raw
        return self


class CreateTargetParam(_ValidatedTargetParam):
    pass


class UpdateTargetParam(_ValidatedTargetParam):
    # Authorizing a target for scanning is a deliberate, separate decision.
    is_authorized: bool | None = None


class AuthorizeTargetParam(SchemaBase):
    is_authorized: bool


class GetTargetDetails(TargetSchemaBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    x_id: str
    is_authorized: bool
    created_time: datetime
    updated_time: datetime | None = None
