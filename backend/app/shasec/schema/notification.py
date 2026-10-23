from datetime import datetime

from pydantic import ConfigDict

from backend.common.schema import SchemaBase


class GetNotificationDetails(SchemaBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    kind: str
    title: str
    body: str | None = None
    link: str | None = None
    is_read: bool
    created_time: datetime
