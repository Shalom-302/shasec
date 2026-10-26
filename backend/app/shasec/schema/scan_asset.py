from datetime import datetime

from pydantic import ConfigDict

from backend.common.schema import SchemaBase


class CreateScanAssetParam(SchemaBase):
    scan_id: int
    host: str
    source: str = 'root'
    url: str | None = None
    ips: str | None = None
    cname: str | None = None
    third_party: str | None = None
    alive: bool = False
    http_status: int | None = None
    title: str | None = None
    server: str | None = None
    kind: str = 'website'
    selected: bool = False


class GetScanAssetDetails(SchemaBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    host: str
    source: str
    url: str | None = None
    ips: str | None = None
    cname: str | None = None
    third_party: str | None = None
    alive: bool = False
    http_status: int | None = None
    title: str | None = None
    server: str | None = None
    kind: str = 'website'
    selected: bool = False


class SelectAssetsParam(SchemaBase):
    asset_ids: list[int]
