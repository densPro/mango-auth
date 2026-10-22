class AuthError(Exception):
    """Expected, client-facing failure. Carries an HTTP status and a stable machine-readable code."""

    code = "auth_error"

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class Unauthorized(AuthError):
    code = "unauthorized"

    def __init__(self, message: str = "Invalid or expired credentials") -> None:
        super().__init__(401, message)


class Forbidden(AuthError):
    code = "forbidden"

    def __init__(self, message: str = "Permission denied") -> None:
        super().__init__(403, message)


class NotFound(AuthError):
    code = "not_found"

    def __init__(self, message: str = "Not found") -> None:
        super().__init__(404, message)


class Conflict(AuthError):
    code = "conflict"

    def __init__(self, message: str) -> None:
        super().__init__(409, message)


class Locked(AuthError):
    code = "locked"

    def __init__(self) -> None:
        super().__init__(423, "Account temporarily locked")


class ServiceUnavailable(AuthError):
    """A dependency (usually the database) is failing; the client may retry."""

    code = "service_unavailable"

    def __init__(self, message: str = "Service temporarily unavailable") -> None:
        super().__init__(503, message)
