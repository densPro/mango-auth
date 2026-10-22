from dataclasses import dataclass


@dataclass(frozen=True)
class RequestContext:
    ip: str | None = None
    request_id: str | None = None
